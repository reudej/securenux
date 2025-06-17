#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#define MAX_PROFILES 256
#define MAX_RULES_PER_PROFILE 1024
#define MAX_PARAMS 16
#define MAX_PARAM_LEN 256
#define MAX_LINE_LEN 4096
#define PROFILES_CONFIG "/etc/securenux_profiles"

// Rule types (same as in eBPF)
#define RULE_ALLOW 0
#define RULE_DENY 1
#define RULE_MANDATORY_ALLOW 2
#define RULE_MANDATORY_DENY 3

// Parameter matching types
#define PARAM_EXACT 0
#define PARAM_WILDCARD 1
#define PARAM_OPTIONAL 2

struct param_match {
    char pattern[MAX_PARAM_LEN];
    int type;
    int absolute_path;
};

struct syscall_rule {
    int syscall_nr;
    int rule_type;
    int priority;
    int param_count;
    struct param_match params[MAX_PARAMS];
    int applies_to_all;
    int except_list[64];
    int except_count;
};

struct profile_data {
    int rule_count;
    struct syscall_rule rules[MAX_RULES_PER_PROFILE];
};

struct process_context {
    pid_t pid;
    pid_t tgid;
    int profile_active;
    int include_self;
};

// Global variables
static struct bpf_object *obj = NULL;
static int profile_map_fd = -1;
static int process_map_fd = -1;
static int events_fd = -1;

// Syscall name to number mapping (simplified)
struct syscall_mapping {
    const char *name;
    int number;
};

static struct syscall_mapping syscall_map[] = {
    {"read", 0}, {"write", 1}, {"open", 2}, {"close", 3},
    {"stat", 4}, {"fstat", 5}, {"lstat", 6}, {"poll", 7},
    {"lseek", 8}, {"mmap", 9}, {"mprotect", 10}, {"munmap", 11},
    {"brk", 12}, {"rt_sigaction", 13}, {"rt_sigprocmask", 14},
    {"rt_sigreturn", 15}, {"ioctl", 16}, {"pread64", 17},
    {"pwrite64", 18}, {"readv", 19}, {"writev", 20}, {"access", 21},
    {"pipe", 22}, {"select", 23}, {"sched_yield", 24}, {"mremap", 25},
    {"msync", 26}, {"mincore", 27}, {"madvise", 28}, {"shmget", 29},
    {"shmat", 30}, {"shmctl", 31}, {"dup", 32}, {"dup2", 33},
    {"pause", 34}, {"nanosleep", 35}, {"getitimer", 36}, {"alarm", 37},
    {"setitimer", 38}, {"getpid", 39}, {"sendfile", 40}, {"socket", 41},
    {"connect", 42}, {"accept", 43}, {"sendto", 44}, {"recvfrom", 45},
    {"sendmsg", 46}, {"recvmsg", 47}, {"shutdown", 48}, {"bind", 49},
    {"listen", 50}, {"getsockname", 51}, {"getpeername", 52},
    {"socketpair", 53}, {"setsockopt", 54}, {"getsockopt", 55},
    {"clone", 56}, {"fork", 57}, {"vfork", 58}, {"execve", 59},
    {"exit", 60}, {"wait4", 61}, {"kill", 62}, {"uname", 63},
    {"semget", 64}, {"semop", 65}, {"semctl", 66}, {"shmdt", 67},
    {"msgget", 68}, {"msgsnd", 69}, {"msgrcv", 70}, {"msgctl", 71},
    {"fcntl", 72}, {"flock", 73}, {"fsync", 74}, {"fdatasync", 75},
    {"truncate", 76}, {"ftruncate", 77}, {"getdents", 78}, {"getcwd", 79},
    {"chdir", 80}, {"fchdir", 81}, {"rename", 82}, {"mkdir", 83},
    {"rmdir", 84}, {"creat", 85}, {"link", 86}, {"unlink", 87},
    {"symlink", 88}, {"readlink", 89}, {"chmod", 90}, {"fchmod", 91},
    {"chown", 92}, {"fchown", 93}, {"lchown", 94}, {"umask", 95},
    {"gettimeofday", 96}, {"getrlimit", 97}, {"getrusage", 98},
    {"sysinfo", 99}, {"times", 100}, {"ptrace", 101}, {"getuid", 102},
    {"syslog", 103}, {"getgid", 104}, {"setuid", 105}, {"setgid", 106},
    {"geteuid", 107}, {"getegid", 108}, {"setpgid", 109}, {"getppid", 110},
    {NULL, -1}
};

static int get_syscall_number(const char *name) {
    for (int i = 0; syscall_map[i].name != NULL; i++) {
        if (strcmp(syscall_map[i].name, name) == 0) {
            return syscall_map[i].number;
        }
    }
    return -1;
}

static char *trim_whitespace(char *str) {
    char *end;
    
    // Trim leading space
    while (*str == ' ' || *str == '\t') str++;
    
    if (*str == 0) return str;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        end--;
    }
    
    end[1] = '\0';
    return str;
}

static int parse_parameter(char *param_str, struct param_match *param) {
    char *p = param_str;
    
    // Check for absolute path prefix
    if (*p == 'a') {
        param->absolute_path = 1;
        p++;
    } else {
        param->absolute_path = 0;
    }
    
    // Skip quotes
    if (*p == '"' || *p == '\'') {
        char quote = *p;
        p++;
        char *end = strchr(p, quote);
        if (end) {
            *end = '\0';
        }
    }
    
    // Determine parameter type
    if (strchr(p, '*') || strchr(p, '?')) {
        param->type = PARAM_WILDCARD;
    } else if (strchr(p, '[') && strchr(p, ']')) {
        param->type = PARAM_OPTIONAL;
    } else {
        param->type = PARAM_EXACT;
    }
    
    strncpy(param->pattern, p, MAX_PARAM_LEN - 1);
    param->pattern[MAX_PARAM_LEN - 1] = '\0';
    
    return 0;
}

static int parse_syscalls(char *syscall_str, struct syscall_rule *rule) {
    char *token;
    char *saveptr;
    
    if (syscall_str[0] == '*') {
        rule->applies_to_all = 1;
        rule->except_count = 0;
        
        // Check for exceptions
        if (strlen(syscall_str) > 1) {
            char *except_str = syscall_str + 1;
            token = strtok_r(except_str, "|", &saveptr);
            while (token && rule->except_count < 64) {
                int syscall_nr = get_syscall_number(trim_whitespace(token));
                if (syscall_nr >= 0) {
                    rule->except_list[rule->except_count++] = syscall_nr;
                }
                token = strtok_r(NULL, "|", &saveptr);
            }
        }
        return 0;
    }
    
    rule->applies_to_all = 0;
    token = strtok_r(syscall_str, "|", &saveptr);
    if (token) {
        rule->syscall_nr = get_syscall_number(trim_whitespace(token));
        return (rule->syscall_nr >= 0) ? 0 : -1;
    }
    
    return -1;
}

static int parse_rule_line(char *line, struct syscall_rule *rule, int priority) {
    char *p = trim_whitespace(line);
    
    if (*p == '\0' || *p == '#') {
        return -1; // Empty line or comment
    }
    
    // Parse rule type prefix
    rule->priority = priority;
    rule->param_count = 0;
    
    switch (*p) {
        case '+':
            rule->rule_type = RULE_MANDATORY_ALLOW;
            p++;
            break;
        case '-':
            rule->rule_type = RULE_MANDATORY_DENY;
            p++;
            break;
        case '!':
            rule->rule_type = RULE_DENY;
            p++;
            break;
        default:
            rule->rule_type = RULE_ALLOW;
            break;
    }
    
    // Find syscall part
    char *syscall_part = p;
    char *param_part = strchr(p, ' ');
    if (param_part) {
        *param_part = '\0';
        param_part++;
    }
    
    // Parse syscalls
    if (parse_syscalls(syscall_part, rule) != 0) {
        return -1;
    }
    
    // Parse parameters
    if (param_part) {
        char *param_copy = strdup(param_part);
        char *param_token;
        char *param_saveptr;
        
        // Handle parameters in braces
        if (*param_part == '{') {
            char *end_brace = strchr(param_part, '}');
            if (end_brace) {
                *end_brace = '\0';
                param_part++;
            }
        }
        
        param_token = strtok_r(param_copy, " \t", &param_saveptr);
        while (param_token && rule->param_count < MAX_PARAMS) {
            if (parse_parameter(param_token, &rule->params[rule->param_count]) == 0) {
                rule->param_count++;
            }
            param_token = strtok_r(NULL, " \t", &param_saveptr);
        }
        
        free(param_copy);
    }
    
    return 0;
}

static int load_profile(const char *filename, struct profile_data *profile) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Cannot open profile file: %s\n", filename);
        return -1;
    }
    
    char line[MAX_LINE_LEN];
    int line_num = 0;
    profile->rule_count = 0;
    
    while (fgets(line, sizeof(line), file) && profile->rule_count < MAX_RULES_PER_PROFILE) {
        line_num++;
        if (parse_rule_line(line, &profile->rules[profile->rule_count], line_num) == 0) {
            profile->rule_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d rules from %s\n", profile->rule_count, filename);
    return 0;
}

static int merge_profiles(struct profile_data *merged, char **profile_files, 
                         int num_files, char **user_profiles, int num_user_profiles) {
    merged->rule_count = 0;
    
    // Load system profiles (higher priority)
    for (int i = 0; i < num_files && merged->rule_count < MAX_RULES_PER_PROFILE; i++) {
        struct profile_data temp_profile;
        if (load_profile(profile_files[i], &temp_profile) == 0) {
            for (int j = 0; j < temp_profile.rule_count && merged->rule_count < MAX_RULES_PER_PROFILE; j++) {
                temp_profile.rules[j].priority += (num_files - i) * 1000;
                merged->rules[merged->rule_count++] = temp_profile.rules[j];
            }
        }
    }
    
    // Load user profiles (lower priority)
    for (int i = 0; i < num_user_profiles && merged->rule_count < MAX_RULES_PER_PROFILE; i++) {
        struct profile_data temp_profile;
        if (load_profile(user_profiles[i], &temp_profile) == 0) {
            for (int j = 0; j < temp_profile.rule_count && merged->rule_count < MAX_RULES_PER_PROFILE; j++) {
                temp_profile.rules[j].priority += (num_user_profiles - i) * 100;
                merged->rules[merged->rule_count++] = temp_profile.rules[j];
            }
        }
    }
    
    printf("Merged profile contains %d rules\n", merged->rule_count);
    return 0;
}

static int load_system_profiles(char ***profile_files, int *num_files) {
    FILE *config = fopen(PROFILES_CONFIG, "r");
    if (!config) {
        fprintf(stderr, "Cannot open system profiles config: %s\n", PROFILES_CONFIG);
        return -1;
    }
    
    char line[MAX_LINE_LEN];
    int count = 0;
    
    // Count lines first
    while (fgets(line, sizeof(line), config)) {
        if (trim_whitespace(line)[0] != '\0' && line[0] != '#') {
            count++;
        }
    }
    
    *profile_files = malloc(count * sizeof(char*));
    *num_files = 0;
    
    rewind(config);
    while (fgets(line, sizeof(line), config) && *num_files < count) {
        char *filename = trim_whitespace(line);
        if (filename[0] != '\0' && filename[0] != '#') {
            (*profile_files)[*num_files] = strdup(filename);
            (*num_files)++;
        }
    }
    
    fclose(config);
    return 0;
}

static int init_bpf() {
    struct bpf_program *prog;
    struct bpf_map *map;
    int err;
    
    // Load BPF object
    obj = bpf_object__open("securenux.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return -1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return -1;
    }
    
    // Get map file descriptors
    map = bpf_object__find_map_by_name(obj, "profile_map");
    if (!map) {
        fprintf(stderr, "Failed to find profile_map\n");
        return -1;
    }
    profile_map_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "process_map");
    if (!map) {
        fprintf(stderr, "Failed to find process_map\n");
        return -1;
    }
    process_map_fd = bpf_map__fd(map);
    
    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "Failed to find events map\n");
        return -1;
    }
    events_fd = bpf_map__fd(map);
    
    // Attach programs
    bpf_object__for_each_program(prog, obj) {
        err = bpf_program__attach(prog);
        if (err) {
            fprintf(stderr, "Failed to attach program %s: %d\n", 
                    bpf_program__name(prog), err);
            return -1;
        }
    }
    
    printf("BPF programs loaded and attached successfully\n");
    return 0;
}

int apply_profile_to_process(pid_t pid, char **user_profiles, int num_user_profiles, 
                           int include_self) {
    char **system_profiles;
    int num_system_profiles;
    
    // Load system profiles
    if (load_system_profiles(&system_profiles, &num_system_profiles) != 0) {
        return -1;
    }
    
    // Merge all profiles
    struct profile_data merged_profile;
    if (merge_profiles(&merged_profile, system_profiles, num_system_profiles,
                      user_profiles, num_user_profiles) != 0) {
        return -1;
    }
    
    // Update BPF maps
    if (bpf_map_update_elem(profile_map_fd, &pid, &merged_profile, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update profile map: %s\n", strerror(errno));
        return -1;
    }
    
    struct process_context ctx = {
        .pid = pid,
        .tgid = pid,
        .profile_active = 1,
        .include_self = include_self
    };
    
    if (bpf_map_update_elem(process_map_fd, &pid, &ctx, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update process map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Profile applied to process %d\n", pid);
    
    // Cleanup
    for (int i = 0; i < num_system_profiles; i++) {
        free(system_profiles[i]);
    }
    free(system_profiles);
    
    return 0;
}

static void cleanup() {
    if (obj) {
        bpf_object__close(obj);
    }
}

static void signal_handler(int sig) {
    printf("\nShutting down...\n");
    cleanup();
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <include_self(0|1)> [profile1] [profile2] ...\n", argv[0]);
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    int include_self = atoi(argv[2]);
    
    char **user_profiles = NULL;
    int num_user_profiles = 0;
    
    // Parse user profiles from command line
    if (argc > 3) {
        num_user_profiles = argc - 3;
        user_profiles = &argv[3];
    }
    
    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize BPF
    if (init_bpf() != 0) {
        fprintf(stderr, "Failed to initialize BPF\n");
        return 1;
    }
    
    // Apply profile to target process
    if (apply_profile_to_process(target_pid, user_profiles, num_user_profiles, include_self) != 0) {
        fprintf(stderr, "Failed to apply profile to process %d\n", target_pid);
        cleanup();
        return 1;
    }
    
    printf("SecureNux monitoring process %d (include_self=%d)\n", target_pid, include_self);
    printf("Press Ctrl+C to stop monitoring\n");
    
    // Event monitoring loop
    struct ring_buffer *rb;
    int err;
    
    rb = ring_buffer__new(events_fd, NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        cleanup();
        return 1;
    }
    
    while (1) {
        err = ring_buffer__poll(rb, 100); // Poll every 100ms
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    ring_buffer__free(rb);
    cleanup();
    return 0;
}