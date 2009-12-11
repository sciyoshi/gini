#include <slack/std.h>
#include <slack/map.h>
#include <slack/prog.h>
#include <slack/err.h>
#include <slack/list.h>
#include <pthread.h>
#include "protocols.h"
#include "packetcore.h"
#include "message.h"
#include "grouter.h"

/*
 * Roundrobin scheduler implementation -- when the roundrobin scheme is used, we need to use
 * the corresponding "queuer" as well.
 */

extern router_config rconfig; 

void *roundRobinScheduler(void *pc)
{
	pktcore_t *pcore = (pktcore_t *)pc;
	List *keylst;
	int nextqid, qcount, rstatus, pktsize;
	char *nextqkey;
	gpacket_t *in_pkt;
	simplequeue_t *nextq;
	

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (1)
	{
		verbose(2, "[roundRobinScheduler]:: Round robin scheduler processing... ");
		keylst = map_keys(pcore->queues);
		nextqid = pcore->lastqid;
		qcount = list_length(keylst);

		pthread_mutex_lock(&(pcore->qlock));
		if (pcore->packetcnt == 0)
			pthread_cond_wait(&(pcore->schwaiting), &(pcore->qlock));	
		pthread_mutex_unlock(&(pcore->qlock));

		pthread_testcancel();
		do 
		{
			nextqid = (1 + nextqid) % qcount;
			nextqkey = list_item(keylst, nextqid);
			// get the queue..
			nextq = map_get(pcore->queues, nextqkey);
			// read the queue..
			rstatus = readQueue(nextq, (void **)&in_pkt, &pktsize);

			if (rstatus == EXIT_SUCCESS)
			{
				pcore->lastqid = nextqid;
				writeQueue(pcore->workQ, in_pkt, pktsize);
			} 

		} while (nextqid != pcore->lastqid && rstatus == EXIT_FAILURE);
		list_release(keylst);

		pthread_mutex_lock(&(pcore->qlock));
		if (rstatus == EXIT_SUCCESS)
			pcore->packetcnt--;
		pthread_mutex_unlock(&(pcore->qlock));

		usleep(rconfig.schedcycle);
	}
}
	


int roundRobinQueuer(pktcore_t *pcore, gpacket_t *in_pkt, int pktsize, char *qkey)
{
	simplequeue_t *thisq;

	verbose(2, "[roundRobinQueuer]:: Round robin queuing scheme.. a very simple queuer invoked..");
	if (prog_verbosity_level() >= 3)
		printGPacket(in_pkt, 6, "QUEUER");

	pthread_mutex_lock(&(pcore->qlock));

	thisq = map_get(pcore->queues, qkey);
	if (thisq == NULL)
	{
		fatal("[roundRobinQueuer]:: Invalid %s key presented for queue addition", qkey);
		pthread_mutex_unlock(&(pcore->qlock));
		free(in_pkt);
		return EXIT_FAILURE;             // packet dropped..
	}

	if (thisq->cursize < thisq->maxsize)
	{
		pcore->packetcnt++;
		if (pcore->packetcnt == 1) 		
			pthread_cond_signal(&(pcore->schwaiting)); // wake up scheduler if it was waiting..
		pthread_mutex_unlock(&(pcore->qlock));
		verbose(2, "[roundRobinQueuer]:: Adding packet.. ");
		writeQueue(thisq, in_pkt, pktsize);
		return EXIT_SUCCESS;
	} else {
		verbose(2, "[roundRobinQueuer]:: Packet dropped.. Queue for [%s] is full.. cursize %d..  ", qkey, thisq->cursize);
		free(in_pkt);
		pthread_mutex_unlock(&(pcore->qlock));
		return EXIT_FAILURE;
	}
}

