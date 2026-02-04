from strategies.base import Strategy, StrategyStatus


class UploadExecutionCheckStrategy(Strategy):
    name = "upload_execution_check"
    description = "Determine if uploaded files are executed or served as static content"
    confidence_gain = 0.9


    def __init__(self, uploader, fetcher, observer):
        """
        uploader: handles file upload 
        fetcher: handles GET requests to uploaded files 
        observer: analyzes HTTP responses 
        """
        self.uploader = uploader 
        self.fetcher = fetcher
        self.observer = observer

        # Filname chosen from previous accepted variants
        self.test_filename = "exec_probe.php.jpg"

        # Marker content - safe, no commands 
        self.marker_payload = b"<?php echo 'EXEC_OK'; ?>"

    def applicable(self, context) -> bool:
        """
        Only run if :
        - uploads are supported
        - naive extension blacklist is suspected
        """
        return (
            context.capabilities.upload_supported and
            context.hypotheses.get("NAIVE_EXTENSION_BLACKLIST", 0) >= 0.6

        )
    
    def execute(self, context)-> StrategyStatus:
        # step1 :uplaod marker file
        upload_reponse = self.uploader.upload(
            filename = self.test_filename,
            content = self.marker_payload
        )
        upload_obs = self.observer.analyze_upload(
            upload_reponse, self.test_filename
            )

        context.record(upload_obs)

        if not upload_obs.accepted:
            return StrategyStatus.FAILURE 
        
        #step2 : request uploaded file
        file_url = upload_obs.file_url
        response = self.fetcher.get(file_url)

        exec_obs = self.observer.analyze_execution(response)
        context.record(exec_obs)


        #step3 : evaluate behavior

        if exec_obs.executed:
            context.hypotheses.increase(
                "UPLOAD_EXECUTION", self.confidence_gain
            )
            return StrategyStatus.SUCCESS
        
        if exec_obs.static:
            context.hypotheses.increase(
                "UPLOAD_STATIC_ONLY",0.8 
            )
            return StrategyStatus.FAILURE
        

        return StrategyStatus.INCONCLUSIVE