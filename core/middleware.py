from django.http import JsonResponse

BLOCKED_IPS = {"192.168.1.1", "10.0.0.2", "127.0.0.1"}

class IPBlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        if client_ip in BLOCKED_IPS:
            return JsonResponse({"error": "Your IP is blocked."}, status=403)

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')