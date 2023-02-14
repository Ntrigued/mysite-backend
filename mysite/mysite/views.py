from django.views import View
from django.cache import cache
from django.conf import settings


class JSONDebugRequestor(Requestor):
    def request(self, *args, **kwargs):
        response = super().request(*args, **kwargs)
        print(json.dumps(response.json(), indent=4))
        self.json_response = response.json()
        return response

class RedditView(View):
    def get(self, request, *args, **kwargs):
        if self.request.groups.filter(name='Reddit Access').exists():
            reddit_url = settings.REDDIT_URL + self.request.GET['reddit_endpoint']
            reddit = praw.Reddit(
                client_id=settings.REDDIT_CLIENT_ID,
                client_secret=settings.REDDIT_CLIENT_SECRET,
                user_agent=f"Server for {settings.REDDIT_USER}",
            )
