// Hlavičkové soubory potřebné pro eBPF programy a přístup k systémovým strukturám a funkcím
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>
#include <linux/string.h>

// Definice limitů pro profily a pravidla
#define MAX_PROFILES 256                   // Maximální počet profilů
#define MAX_RULES_PER_PROFILE 1024        // Maximální počet pravidel na profil
#define MAX_SYSCALLS 512                  // Maximální počet systémových volání
#define MAX_PARAMS 16                    // Maximální počet parametrů v jednom pravidle
#define MAX_PARAM_LEN 256               // Maximální délka jednoho parametru (např. cesta)
#define MAX_PARAM_DEPTH 64
#define MAX_PATH_LEN 4096              // Maximální délka cesty

// Typy pravidel
#define RULE_ALLOW 0                 // Povolit volání
#define RULE_DENY 1                  // Zakázat volání
#define RULE_MANDATORY_ALLOW 2       // Povinně povolit (přetlačí jiné)
#define RULE_MANDATORY_DENY 3        // Povinně zakázat

// Typy porovnávání parametrů
#define PARAM_EXACT 0               // Přesné porovnání
#define PARAM_WILDCARD 1            // Podpora zástupných znaků
#define PARAM_OPTIONAL 2            // Volitelný parametr (vždy se shoduje)

// Struktura pro porovnávání parametru
struct param_match {
    char pattern[MAX_PARAM_LEN];    // Vzor pro porovnání
    int type;                       // Typ porovnání
    int absolute_path;              // Příznak, zda jde o absolutní cestu
};

// Struktura pro jedno pravidlo
struct syscall_rule {
    int syscall_nr;                // Číslo systémového volání
    int rule_type;                 // Typ pravidla (viz výše)
    int priority;                  // Priorita pravidla
    int param_count;               // Počet parametrů k ověření
    struct param_match params[MAX_PARAMS]; // Parametry
    int applies_to_all;           // Příznak, zda platí na všechna syscalls kromě výjimek
    int except_list[64];          // Seznam výjimek
    int except_count;             // Počet výjimek
};

// Struktura dat profilu
struct profile_data {
    int rule_count;                              // Počet pravidel v profilu
    struct syscall_rule rules[MAX_RULES_PER_PROFILE]; // Pole pravidel
};

// Kontext procesu
struct process_context {
    pid_t pid;              // PID procesu
    pid_t tgid;             // TGID (skupina procesů)
    int profile_active;     // Příznak, zda má aktivní profil
    int include_self;       // Zda se má monitorovat i hlavní proces (nejen potomci)
};

// eBPF mapy
struct {
    __uint(type, BPF_MAP_TYPE_HASH);                // Hash mapa profilů
    __uint(max_entries, MAX_PROFILES);
    __type(key, pid_t);                             // Klíč = TGID
    __type(value, struct profile_data);             // Hodnota = profil
} profile_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);                // Mapa kontextu procesu
    __uint(max_entries, 65536);
    __type(key, pid_t);                             // Klíč = TGID
    __type(value, struct process_context);          // Hodnota = kontext
} process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);             // Ring buffer pro události
    __uint(max_entries, 256 * 1024);                // Velikost bufferu
} events SEC(".maps");

// Struktura zaznamenané události syscallu
struct syscall_event {
    pid_t pid;               // PID volajícího procesu
    pid_t tgid;              // TGID volajícího procesu
    int syscall_nr;          // Číslo volání
    int action;              // Akce: 0 = povoleno, 1 = zakázáno
    char comm[16];           // Jméno procesu
    unsigned long args[6];   // Argumenty syscallu
};

int concatchr(char *str, char chr, int pozice) {
    *str[pozice] = chr;
    *str[pozice+1] = '\0';
}


char* getstar(char *star, int act_depth) {
    return star[act_depth];
}
void setstar(char **star, int act_depth, char *new_pointer) {
    **star[act_depth] = new_pointer;
}

// Pomocná funkce pro porovnávání řetězců se zástupnými znaky
static inline int match_wildcard(const char *pattern, const char *text) {
    const char *p = pattern;
    const char *t = text;
    const char *star[MAX_PARAM_DEPTH] = {NULL};
    const char *match = NULL;
    int backslash = 0;
    char open_brackets[MAX_PARAM_DEPTH] = "";
    char *open_brackets_ptrs[MAX_PARAM_DEPTH] = {NULL};
    int act_depth = 0;
    int mode = 0;
    char **act_star;
    act_star = &star[act_depth];

    while (*t) {
        if (mode && (*p == '|' || *p == ']' || *p == ')')) {
            if (*p == '|') t = *open_brackets_ptrs[act_depth - 1];
            else {
                open_brackets[act_depth - 1] = '\0';
                open_brackets_ptrs[act_depth - 1] = NULL;
            }
        } else if (!mode && *p == '\\' && !backslash) backslash = 1;
        else  {
            if (*p == '*' && !backslash) {
                *act_star = p;      // Hvězdička = libovolný počet znaků
                match = t;
            } else if ((*p == "[" || *p == "(" ) && !backslash) {
                concatchr(&open_brackets, *p, act_depth++);
            } else if ((*p == '?' && !backslash) || *p == *t) {
                t++;        // Otazník = libovolný jeden znak nebo přesná shoda
            } else if (act_depth > 0) {
                mode = 1;
            } else if (*act_star) {
                p = *act_star + 1;    // Vrátit se na předchozí hvězdičku
                t = ++match;
            } else {
                return 0;        // Neshoda
            }
            backslash = 0;
        }
        p++;
    }

    while (*p == '*') p++;   // Přeskočit koncové hvězdičky
    return !*p;              // Pokud jsme na konci patternu, vrátit úspěch
}

// Pomocná funkce pro porovnání jednoho parametru
static inline int match_parameter(struct param_match *param, const char *value) {
    switch (param->type) {
        case PARAM_EXACT:
            return bpf_strncmp(param->pattern, value, MAX_PARAM_LEN) == 0;
        case PARAM_WILDCARD:
            return match_wildcard(param->pattern, value);
        case PARAM_OPTIONAL:
            return 1; // Volitelný parametr vždy vyhovuje
        default:
            return 0;
    }
}

// Zkontroluje, jestli syscall je ve výjimečném seznamu pravidla
static inline int is_syscall_in_except_list(struct syscall_rule *rule, int syscall_nr) {
    for (int i = 0; i < rule->except_count; i++) {
        if (rule->except_list[i] == syscall_nr) {
            return 1;
        }
    }
    return 0;
}

// Ověření, zda dané pravidlo platí na syscall a jeho parametry
static inline int check_syscall_rule(struct syscall_rule *rule, int syscall_nr, 
                                   unsigned long *args) {
    if (!rule->applies_to_all) {
        if (rule->syscall_nr != syscall_nr) {
            return -1; // Pravidlo se nevztahuje na tento syscall
        }
    } else {
        if (is_syscall_in_except_list(rule, syscall_nr)) {
            return -1; // Syscall je ve výjimkách
        }
    }

    if (rule->param_count > 0) {
        char param_buf[MAX_PARAM_LEN];

        for (int i = 0; i < rule->param_count && i < 6; i++) {
            long ret = bpf_probe_read_user_str(param_buf, sizeof(param_buf), 
                                             (void *)args[i]); // Načtení parametru z userspace
            if (ret < 0) {
                continue; // Nepovedlo se načíst, přeskočit
            }

            if (!match_parameter(&rule->params[i], param_buf)) {
                return -1; // Parametr nesedí
            }
        }
    }

    return rule->rule_type; // Vrátit typ pravidla
}

// Hlavní logika pro vyhodnocení volání na základě profilu
static inline int evaluate_syscall(pid_t pid, int syscall_nr, unsigned long *args) {
    struct profile_data *profile = bpf_map_lookup_elem(&profile_map, &pid);
    if (!profile) {
        return RULE_ALLOW; // Pokud není profil, povolit
    }

    int final_decision = RULE_ALLOW;
    int highest_priority = -1;

    for (int i = 0; i < profile->rule_count; i++) {
        struct syscall_rule *rule = &profile->rules[i];
        int rule_result = check_syscall_rule(rule, syscall_nr, args);

        if (rule_result >= 0) {
            if (rule->priority > highest_priority) {
                highest_priority = rule->priority;
                final_decision = rule_result;
            } else if (rule->priority == highest_priority) {
                if (rule_result == RULE_MANDATORY_ALLOW || 
                    rule_result == RULE_MANDATORY_DENY) {
                    final_decision = rule_result; // Povinné pravidlo má přednost
                }
            }
        }
    }

    return final_decision;
}

// eBPF handler pro tracepoint při vstupu do systémového volání
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    pid_t tgid = bpf_get_current_pid_tgid() >> 32;

    struct process_context *proc_ctx = bpf_map_lookup_elem(&process_map, &tgid);
    if (!proc_ctx || !proc_ctx->profile_active) {
        return 0;
    }

    if (!proc_ctx->include_self && pid == tgid) {
        return 0;
    }

    int syscall_nr = ctx->id;
    unsigned long args[6];
    args[0] = ctx->args[0];
    args[1] = ctx->args[1];
    args[2] = ctx->args[2];
    args[3] = ctx->args[3];
    args[4] = ctx->args[4];
    args[5] = ctx->args[5];

    int decision = evaluate_syscall(tgid, syscall_nr, args);

    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->pid = pid;
        event->tgid = tgid;
        event->syscall_nr = syscall_nr;
        event->action = (decision == RULE_DENY || decision == RULE_MANDATORY_DENY) ? 1 : 0;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        for (int i = 0; i < 6; i++) {
            event->args[i] = args[i];
        }
        bpf_ringbuf_submit(event, 0);
    }

    if (decision == RULE_DENY || decision == RULE_MANDATORY_DENY) {
        return -1; // Syscall by měl být zablokován (v reálu pomocí LSM hooku)
    }

    return 0;
}

// Tracepoint pro vytvoření nového procesu (fork)
SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    pid_t parent_tgid = ctx->parent_pid;
    pid_t child_tgid = ctx->child_pid;

    struct process_context *parent_ctx = bpf_map_lookup_elem(&process_map, &parent_tgid);
    if (parent_ctx && parent_ctx->profile_active) {
        struct process_context child_ctx = *parent_ctx;
        child_ctx.pid = child_tgid;
        child_ctx.tgid = child_tgid;

        bpf_map_update_elem(&process_map, &child_tgid, &child_ctx, BPF_ANY);

        struct profile_data *parent_profile = bpf_map_lookup_elem(&profile_map, &parent_tgid);
        if (parent_profile) {
            bpf_map_update_elem(&profile_map, &child_tgid, parent_profile, BPF_ANY);
        }
    }

    return 0;
}

// Tracepoint pro ukončení procesu – odstraní záznamy z map
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    pid_t tgid = ctx->pid;

    bpf_map_delete_elem(&process_map, &tgid);
    bpf_map_delete_elem(&profile_map, &tgid);

    return 0;
}

// Licence programu pro eBPF (musí být GPL)
char LICENSE[] SEC("license") = "GPL";
