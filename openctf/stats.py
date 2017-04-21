from openctf.services import celery


@celery.task
def compute_ranked_scoreboard():
    print("COMPUTE ranked SCOREBOARD")
    pass


@celery.task
def compute_all_scoreboard():
    print("COMPUTE all SCOREBOARD")
    pass
