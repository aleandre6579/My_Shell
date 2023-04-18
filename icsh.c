/*  ICCS227: Project 1: icsh
    Name:  Alexandre Simon
    StudentID: 6380359 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <stdbool.h>
#define MAX_CMD_BUFFER 255
int prev_code = 0;

struct Job {
  size_t num;
  char* cmd;
  int* status;
  int pid;
  bool bg;
};

struct Job* jobs;
int jobs_n = 0;

char* run_cmd(char* cmd, char* prev_cmd, int is_script, bool is_bg);
int process_script(char const* const filename);
void run_ext_cmd(char* ext_cmd, bool is_bg);
void childDone(int num);
void checkDoneJobs();
void printJobs();
void removeJob(size_t num);

bool is_bg(char* cmd) {
  char* tmp_cmd = malloc(strlen(cmd));
  strcpy(tmp_cmd, cmd);
  char* token = tmp_cmd;
  char* prev_tok;
  token = strtok(tmp_cmd, " ");
  while((token = strtok(NULL, " ")) != NULL) {
    prev_tok = token;
  }

  if(strcmp(prev_tok, "&") == 10) {
    free(tmp_cmd);
    cmd[strlen(cmd)-3] = '\0'; // Remove '&' from cmd
    return true;
  }
  free(tmp_cmd);
  return false;
}

void blockSig(int num)
{
  // Make the signal do nothing
}

int change_out(char* out) {
  int out_num = open(out, O_TRUNC | O_CREAT | O_WRONLY, 0666);
  if(out_num <= 0) fprintf(stdout, "OUPTUT FILE ERROR\n");
  dup2(out_num, 1);
  close(out_num);
  return out_num;
}

int change_in(char* in) {
  int in_num = open(in, O_RDONLY);
  if(in_num <= 0) fprintf(stderr, "INPUT FILE ERROR\n");
  dup2(in_num, 0);
  close(in_num);
  return in_num;
}

int main(int argc, char* argv[])
{
  //Setup for changing signal actions
  struct sigaction ign_action;
  ign_action.sa_handler = blockSig;
  ign_action.sa_flags = SA_RESTART;
  sigaction(SIGTSTP, &ign_action, NULL);
  sigaction(SIGINT, &ign_action, NULL);

  //Handling child signals
  struct sigaction done_action;
  done_action.sa_handler = childDone;
  done_action.sa_flags = SA_RESTART;
  sigaction(SIGCHLD, &done_action, NULL);

  if(argc > 1) {
    return process_script(argv[1]);
  }

  char buffer[MAX_CMD_BUFFER];
  char prev_cmd[MAX_CMD_BUFFER];
  printf("Starting IC Shell\n");

  while (1) {
    printf("icsh $ ");
    fgets(buffer, 255, stdin);

    if(strcmp(buffer, "") == 10) {
      checkDoneJobs(jobs_n);
      continue;
    }

    char* cmd_ptr = buffer;
    char* prev_cmd_ptr = prev_cmd;
    char* cmd_used = run_cmd(cmd_ptr, prev_cmd_ptr, 0, is_bg(cmd_ptr)); // RUN COMMAND

    if(strcmp(cmd_used, "exit") == 0) {
      break;
    }
    if(strcmp(cmd_used, "") != 0) {
      strcpy(prev_cmd, cmd_used);
    }

    checkDoneJobs(jobs_n);
  }

  char *token = strtok(buffer, " ");
  token = strtok(NULL, " ");
  if(token != NULL)
    return atoi(token) & 0xFF;  // returns truncated exit code
  else
    return 0; // returns default exit code
}

void childDone(int num) {
  //fprintf(stdout, "NUM:%d\n", num);
}

void printJobs() {
  for(int i = 0; i < jobs_n - 1; i++) {
    printf("[%ld] %s, status: %d, pid: %d\n", jobs[i].num, jobs[i].cmd, *jobs[i].status,
    				              jobs[i].pid);
  }
}

void removeJob(size_t num) {
  size_t i_new = 0;
  for(int i = 0; i < jobs_n - 1; i++) {
    if(jobs[i].num == num) {
      //printf("Job deleted: %ld, %s\n", jobs[i].num, jobs[i].cmd);
      free(jobs[i].cmd);
      free(jobs[i].status);
      continue;
    }
    jobs[i_new] = jobs[i];
    jobs[i_new].num = i_new + 1;
    i_new++;
  }

  jobs_n--;
  jobs = realloc(jobs, jobs_n * sizeof(struct Job));
}

void checkDoneJobs() {
  if(jobs_n == 0) {
    //printf("No jobs.\n");
    return;
  }

  for(size_t i = 0; i < jobs_n - 1; i++) {
    waitpid(jobs[i].pid, jobs[i].status, WNOHANG);

    if(WIFEXITED(*jobs[i].status)) {
      printf("[%ld] Done. %s\n", jobs[i].num, jobs[i].cmd);
      removeJob(jobs[i].num);
    }
  }
}

void run_ext_cmd(char* ext_cmd, bool is_bg)
{
  // I/O Redirection variables
  int in;
  int out;
  int new_in = -1;
  int new_out;
  size_t got;
  int saved_stdin = dup(0);
  int saved_stdout = dup(1);

  // Job Management variables
  int* status = malloc(sizeof(int));
  int cpid;
  int ppid = getpid();
  sigset_t blocked;

  int word_count = 0;
  char* tmp_cmd = malloc(strlen(ext_cmd));
  strcpy(tmp_cmd, ext_cmd);
  char* token = strtok(tmp_cmd, " ");

  while(token != NULL) {
    word_count++;
    token = strtok(NULL, " ");
  }

  strcpy(tmp_cmd, ext_cmd);

  char **prog_argv = malloc(word_count * sizeof(char*));
  token = strtok(tmp_cmd, " ");
  int i = 0;
  char path[30] = "/usr/bin/";

  while(token != NULL) { // Create an array with the arguments of the  external command
      if(strcmp(token, ">") == 0) {
        new_out = change_out(token = strtok(NULL, " "));
        break;
      }
      else if(strcmp(token, "<") == 0) {
        new_in = change_in(token = strtok(NULL, " "));
	break;
      }

    if(i == 0) {
      prog_argv[0] = strcat(path, token);
    }
    else prog_argv[i] = token;
    i++;
    token = strtok(NULL, " ");
  }

  if((cpid=fork()) < 0) {
    perror("Fork failed");
    exit(errno);
  }
  if(!cpid) { // Child code
    setpgid(0, 0);

    signal(SIGTSTP, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    char **args = &prog_argv[0];
    if(new_in == -1) prev_code = execvp(prog_argv[0], prog_argv);
    else prev_code = execvp(prog_argv[0], args);

    if(prev_code < 0) {
      fprintf(stderr, "Bad Command\n");
      exit(1);
    }
    exit(-1);
  }
  if(cpid) { // Parent code

    if(is_bg) {
      jobs_n++;
      jobs = realloc(jobs, jobs_n * sizeof(struct Job));
      char* job_cmd = malloc(strlen(ext_cmd));
      strcpy(job_cmd, ext_cmd);

      struct Job job = { .num = jobs_n, .cmd = job_cmd, .status = status, .pid = cpid, .bg = is_bg };
      jobs[jobs_n-1] = job;
      //printf("Job Created:%ld, %s, %d, %d, %d\n", job.num, job_cmd, *job.status, job.pid, job.bg);
    }

    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    setpgid(cpid, cpid);
    setpgid(ppid, ppid);

    if(is_bg) {
      waitpid(cpid, status, WNOHANG);
      if(status >= 0)
        printf("[%d] %d\n", jobs_n, cpid);
    }
    else
      waitpid(cpid, status, 0);
  }

  free(tmp_cmd);
  free(prog_argv);
}

char* run_cmd(char* cmd, char* prev_cmd, int is_script, bool is_bg) {
  cmd[strcspn(cmd, "\n")] = 0; // Remove newline from cmd

  char* tmp_cmd = malloc(strlen(cmd)); // Create duplicate of cmd to tokenize
  strcpy(tmp_cmd, cmd);
  char* token = strtok(tmp_cmd, " ");

  if(strcmp(token, "bg") == 0 || strcmp(token, "fg") == 0 || strcmp(token, "jobs") == 0 || strcmp(token, "echo") == 0 || strcmp(token, "!!") == 0 || strcmp(token, "exit") == 0) {

    if(strcmp(token, "bg") == 0) {
      if(jobs_n == 0) {
	free(tmp_cmd);
	return cmd;
      }
      token = strtok(NULL, " ");
      int num = 0;
      if(token != NULL) {
        num = atoi(token);
      }
      tcsetpgrp(1, jobs[num].pid);
    }
    else if(strcmp(token, "fg") == 0) {
      if(jobs_n == 0) {
	free(tmp_cmd);
	return cmd;
      }
      token = strtok(NULL, " ");
      int num = 0;
      if(token != NULL) {
        num = atoi(token);
      }
      tcsetpgrp(0, jobs[num].pid);
    }
    else if(strcmp(token, "jobs") == 0) {
      printJobs();
      free(tmp_cmd);
      return cmd;
    }
    else if(strcmp(token, "echo") == 0) {
      token = strtok(NULL, " ");
      FILE *out = NULL;
      while(token != NULL) {
        if(strcmp(token, ">") == 0) {
	  out = fopen(token = strtok(NULL, " "), "w");
          break;
        }
        token = strtok(NULL, " ");
      }

      strcpy(tmp_cmd, cmd);
      token = strtok(tmp_cmd, " ");
      token = strtok(NULL, " ");
      while(token != NULL) {
        if(strcmp(token, "$?") == 0) {
	  printf("%d", prev_code);
          break;
        }
	else if(strcmp(token, ">") == 0 || strcmp(token, "<") == 0)
	  break;

	if(out != NULL) fprintf(out, "%s ", token);
	else printf("%s ", token);
        token = strtok(NULL, " ");
      }
      if(out != NULL) fclose(out);
      printf("\n");
      prev_code = 0;
      free(tmp_cmd);
      return cmd;
    }
    else if(strcmp(token, "!!") == 0) {
      if(strcmp(prev_cmd, "") == 0) {
        printf("No previous command\n");
      }
      else {
	if(is_script == 0)
	  printf("%s\n", prev_cmd);
        fflush(stdout);
 	free(tmp_cmd);
        return run_cmd(prev_cmd, NULL, is_script, is_bg);
      }
    }
    else if(strcmp(token, "exit") == 0) {
      if(!is_script)
	printf("Have a good day\n");
      free(tmp_cmd);
      return "exit";
    }
  }
  else {
    // Here we assume it's an external command
    run_ext_cmd(cmd, is_bg);
    free(tmp_cmd);
    return cmd;
  }
}

int process_script(char const* const filename) {
  FILE* file = fopen(filename, "r");
  char line[MAX_CMD_BUFFER];
  char* exit_code;

  while(fgets(line, sizeof(line), file)) { //Iterate over each line of given file

    if(strcmp(line, "") == 10 || line[0] == '#') { //Ignore if line is "" or a comment
      continue;
    }

    char prev_cmd[MAX_CMD_BUFFER];
    char* cmd_ptr = line;
    char* prev_cmd_ptr = prev_cmd;
    char* cmd_used = run_cmd(cmd_ptr, prev_cmd_ptr, 1, is_bg(cmd_ptr));

    if(strcmp(cmd_used, "exit") == 0) {
      exit_code = cmd_used;
      break;
    }
    if(strcmp(cmd_used, "") != 0) {
      strcpy(prev_cmd, cmd_used);
    }
  }

  fclose(file);
  char* token = strtok(line, " ");
  token = strtok(NULL, " ");
  return atoi(token) & 0xFF;
}

