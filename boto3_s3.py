from botocore.history import get_global_history_recorder
import boto3
from boto3.s3.transfer import S3Transfer, TransferConfig
import logging


log = logging.getLogger(__name__)

def main():
    boto3.set_stream_logger(name="", format_string="%(asctime)s %(name)s [%(levelname)s] %(threadName)s %(filename)s %(lineno)d: %(message)s")
    s3 = boto3.client('s3')

    recorder = get_global_history_recorder()
    recorder.add_handler(HistoryEventHandler())
    recorder.enable()
    config = TransferConfig(multipart_threshold=1 * 1024 * 1024 * 1024)  # 1 GiB
    transfer = S3Transfer(client=s3, config=config)
    transfer.upload_file("/Users/dacut/test-file", "kanga", "auth-flow/test-object/test-file")

class HistoryEventHandler:
    def emit(self, event_type, payload, source):
        if event_type == "HTTP_REQUEST":
            log.debug("Botocore HTTP Request: %s", payload)

if __name__ == "__main__":
    main()
