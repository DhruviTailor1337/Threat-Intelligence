"""
TIP Main Runner
Orchestrates the full pipeline: ingest → normalize → enforce → alert
Can be run as a one-shot or scheduled daemon.
"""

import os
import time
import logging
import schedule
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/main.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

os.makedirs("logs", exist_ok=True)

from osint.aggregator    import run_all_feeds
from siem.normalizer     import update_risk_scores_in_mongo, push_to_elasticsearch
from enforcer.enforcer   import enforce_once
from enforcer.alerting   import alert_new_blocks


def full_pipeline():
    logger.info(f"\n{'='*60}\nPipeline run started at {datetime.utcnow()}\n{'='*60}")
    run_all_feeds()
    update_risk_scores_in_mongo()
    push_to_elasticsearch()
    enforce_once()
    alert_new_blocks(since_minutes=60)
    logger.info("Pipeline run complete.\n")


if __name__ == "__main__":
    import sys
    if "--once" in sys.argv:
        full_pipeline()
    else:
        # Run immediately then every hour
        full_pipeline()
        schedule.every(1).hours.do(full_pipeline)
        logger.info("Scheduler started. Pipeline will run every hour.")
        while True:
            schedule.run_pending()
            time.sleep(60)
