/*
 * router.c (GINI router)
 */

//#include <mcheck.h>
#include <slack/std.h>
#include <slack/err.h>
#include <slack/prog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "packetcore.h"
#include "classifier.h"
#include "udp.h"
#include "filter.h"
#include <pthread.h>

router_config rconfig = {.router_name=NULL, .gini_home=NULL, .cli_flag=0, .config_file=NULL, .config_dir=NULL, .ghandler=0, .clihandler= 0, .scheduler=0, .worker=0, .schedcycle=10000, .schedpolicy="rr"};
pktcore_t *pcore;
classlist_t *classifier;
filtertab_t *filter;


Option grouter_optab[] =
{
	{
		"interactive", 'i', "0 or 1", "CLI on for interactive mode (daemon otherwise)",
		required_argument, OPT_INTEGER, OPT_VARIABLE, &(rconfig.cli_flag)
	},
	{
		"config", 'c', "path", "Specify the configuration file",
		optional_argument, OPT_STRING, OPT_VARIABLE, &(rconfig.config_file)
	},
	{
		"confpath", 'p', "path", "Specify directory with configuration files",
		required_argument, OPT_STRING, OPT_VARIABLE, &(rconfig.config_dir)
	},
	{
		NULL, '\0', NULL, NULL, 0, 0, 0, NULL
	}
};

Options options[1] = {{ prog_options_table, grouter_optab }};

void setupProgram(int ac, char *av[]);
void removePIDFile();
int makePIDFile(char *rname, char rpath[]);
void shutdownRouter();
int isPIDAlive(int pid);


int main(int ac, char *av[])
{
	char rpath[MAX_NAME_LEN];
	int status, *jstatus;
	simplequeue_t *outputQ, *workQ, *qtoa;

	// setup the program properties
	setupProgram(ac, av);
	// creates a PID file under router_name.pid in the current directory
	status = makePIDFile(rconfig.router_name, rpath);
	// shutdown the router on receiving SIGUSR1 or SIGUSR2
	redefineSignalHandler(SIGUSR1, shutdownRouter);
	redefineSignalHandler(SIGUSR2, shutdownRouter);

	outputQ = createSimpleQueue("outputQueue", INFINITE_Q_SIZE, 0, 1);
	workQ = createSimpleQueue("work Queue", INFINITE_Q_SIZE, 0, 1);

	GNETInit(&(rconfig.ghandler), rconfig.config_dir, rconfig.router_name, outputQ);
	ARPInit();
	IPInit();

	grtr_udp_init ();

	classifier = createClassifier();
	filter = createFilter(classifier, 0);

	pcore = createPacketCore(rconfig.router_name, outputQ, workQ);

	// add a default Queue.. the createClassifier has already added a rule with "default" tag
	// char *qname, char *dqisc, double qweight, double delay_us, int nslots);
	addPktCoreQueue(pcore, "default", "fifo", 1.0, 2.0, 0);
	rconfig.scheduler = PktCoreSchedulerInit(pcore);
	rconfig.worker = PktCoreWorkerInit(pcore);

	infoInit(rconfig.config_dir, rconfig.router_name);
	addTarget("Output Queue", outputQ);
	qtoa = getCoreQueue(pcore, "default");
	if (qtoa != NULL)
		addTarget("Default Queue", qtoa);
	else
		printf("Error .. found null queue for default\n");

	// start the CLI..
	CLIInit(&(rconfig));


	wait4thread(rconfig.scheduler);
	wait4thread(rconfig.worker);
	wait4thread(rconfig.ghandler);
}


void wait4thread(pthread_t threadid)
{
	int *jstatus;
	if (threadid > 0)
		pthread_join(threadid, (void **)&jstatus);
}


void shutdownRouter()
{
	verbose(1, "[main]:: shutting down the GNET handler...");
	GNETHalt(rconfig.ghandler);
	verbose(1, "[main]:: shutting down the packet core... "); fflush(stdout);
	pthread_cancel(rconfig.scheduler);
	pthread_cancel(rconfig.worker);
	verbose(1, "[main]:: shutting down the CLI handler.. ");
	pthread_cancel(rconfig.clihandler);

	// we should cancel CLI thread too??
	verbose(1, "[main]:: removing the PID files... ");
	removePIDFile();
}


void setupProgram(int ac, char *av[])
{
	int indx;

	prog_init();
	prog_set_syntax("[options] router_name");
	prog_set_options(options);
	prog_set_version("2.0");
	prog_set_date("20090730");
	prog_set_author("Muthucumaru Maheswaran <maheswar@cs.mcgill.ca>");
	prog_set_contact(prog_author());
	prog_set_url("http://www.cs.mcgill.ca/~anrl/gini/");
	prog_set_desc("GINI router provides a user-space IP router for teaching and learning purposes.");

	prog_set_verbosity_level(1);

	indx = prog_opt_process(ac, av);

	if (indx < ac)
		rconfig.router_name = strdup(av[indx]);

	if (rconfig.router_name == NULL)
	{
		prog_usage_msg("\n[setupProgram]:: Router name missing.. \n\n");
		exit(1);
	}
	prog_set_name(rconfig.router_name);
	rconfig.gini_home = getenv("GINI_HOME");
	if (rconfig.gini_home == NULL)
	{
		verbose(2, "\n[setupProgram]:: Environment variable GINI_HOME is not set..\n\n");
		exit(1);
	}

}




int makePIDFile(char *rname, char rpath[])
{
	FILE *fp;
	int pid;

	// initialize the config directory..
	if (rconfig.config_dir == NULL)
		rconfig.config_dir = strdup(".");
	sprintf(rpath, "%s/%s.pid", rconfig.config_dir, rname);

	if ((fp = fopen(rpath, "r")) != NULL)
	{
		// another router could be running or left without cleanup!!
		fscanf(fp, "%d", &pid);
		if (isPIDAlive(pid))
		{
			fatal("[makePIDFile]:: Another router is still running under: %s \n", rpath);
			exit(1);
		} else
		{
			remove(rpath);
		}
	}


	if ((fp = fopen(rpath, "w")) == NULL)
	{
		fatal("[makePIDFile]:: ERROR!! unable to create PID file...%s", rpath);
		exit(1);
	}

	fprintf(fp, "%d\n", getpid());
	fclose(fp);

	return TRUE;
}


void removePIDFile()
{
	char rpath[MAX_NAME_LEN];

	sprintf(rpath, "%s/%s.pid", rconfig.config_dir, prog_name());
	remove(rpath);
}


int isPIDAlive(int pid)
{
	if (kill(pid, 0) < 0)
	{
		if (errno == ESRCH)
			return FALSE;

		// this return should never happen..
		return FALSE;
	}
	return TRUE;
}


