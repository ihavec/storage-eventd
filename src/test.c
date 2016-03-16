#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

volatile bool exiting;

void
sigint(int signum)
{
	exiting = true;
	pthread_cond_broadcast(&cond);
}

void *loop(void *ignored)
{
	while(1) {
		fprintf(stderr, "entering\n");
		pthread_mutex_lock(&lock);
		pthread_cond_wait(&cond, &lock);
		pthread_mutex_unlock(&lock);
		fprintf(stderr, "exiting\n");
	}

	return NULL;
}

int
main(void)
{
	pthread_t tid;
	int ret;
	void *pret;

	signal(SIGINT, sigint);

	ret = pthread_create(&tid, NULL, loop, NULL);

	if (ret) {
		perror("pthread_create");
		return 1;
	}

	while (!exiting)
		sleep(1);

	fprintf(stderr, "Cleaning up..\n");

	pthread_cancel(tid);
	pthread_join(tid, &pret);

	return 0;
}
