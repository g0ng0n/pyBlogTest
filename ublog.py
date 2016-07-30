import os
import webapp2
import jinja2
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
    
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

### Blog Classes

def blog_key(name = "default"):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent= blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(Handler):
    def get(self):
        self.render("new_post.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            a = Post(parent = blog_key(), subject = subject, content = content)
            a.put()
            self.redirect("/blog/%s" % str(a.key().id() ))
        else:
            error = "You need to add some title and a body to this post"
            self.render_front(subject, content, error = error)

class BlogIndex(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render("index.html", posts = posts)



app = webapp2.WSGIApplication([
    ('/blog/?', BlogIndex),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
], debug=True)
