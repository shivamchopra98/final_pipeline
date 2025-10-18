# utils/logging_utils.py
import logging
from datetime import datetime

def setup_logging():
    log_filename = f"sync_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(),
        ],
    )
    log = logging.getLogger("vuln-sync")
    log.info(f"📄 Logs will be saved to {log_filename}")
    return log
