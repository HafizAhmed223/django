class SimpleLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # --- CODE HERE RUNS BEFORE THE VIEW (Request) ---
        print(f"Request coming from: {request.META.get('HTTP_USER_AGENT')}")

        response = self.get_response(request)

        # --- CODE HERE RUNS AFTER THE VIEW (Response) ---
        print("Response is leaving Django...")
        
        return response