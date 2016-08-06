import os
import re
import random
import webapp2
import jinja2
import hashlib
import hmac
import time

from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

secret = 'cf93114d1e000d49e74d6ca87a42a1a8'  # pedito hasheado


## UTIL METHODS
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s, %s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

## MAIN HANDLER
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


## MODEL CLASSES
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    user_id = db.IntegerProperty(required=True)
    liked = db.ListProperty(int, required=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self,user,permalink):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("post.html", post=self, user=user,
                          author=User.by_id(self.user_id),
                          permalink=permalink)

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

    # the comment Model
class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    liked = db.ListProperty(int, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("comment.html", c=self, user=user,
            author=User.by_id(int(self.user_id)))

## END MODEL CLASSES



## CONTROLLERS CLASSES
class BlogFront(BlogHandler):
    def get(self):
        print("llego al get del blogFont")

        posts = Post.all().order('-created')
        self.render('index.html', posts=posts, user=self.user)


class PostPage(BlogHandler):
    def get(self, post_id):
        print("llego al get del postpage")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)



class EditPost(BlogHandler):
    def get(self, post_id):
        print("llego al get")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("edit_post.html", post=post)

    def post(self, post_id):
        print("llego al POST")
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)


            if not post:
                self.error(404)
                return
            if self.user.key().id() == post.user_id:
                post.content = content
                post.subject = subject

                post.put();
                self.redirect('/posts/%s' % str(post.key().id()))
            else:
                print(self.user.name != post.user_id)
                error = "you are not allowed to edit this post!"
                self.render("edit_post.html", post=post, error=error)

        else:
            error = "subject and content, please!"
            self.render("edit_post.html", subject=subject, content=content, error=error)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("new_post.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content, user_id=self.user.key().id())
            p.put()
            self.redirect('/posts/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("new_post.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
    def get(self,post_id):
        print("llego al get del delete Post")

        if self.user:
            post = Post.by_id(int(post_id))

            if not post:
                self.error(404)
                return

            if post.user_id != self.user.key().id():
                self.redirect("/blog")

            self.render("delete_post.html", post=post)
        else:
            self.redirect("/login")

    def post(self,post_id):
        print("llego al POST del delete Post")

        if not self.user:
            self.redirect('/blog')

        post = Post.by_id(int(post_id))

        if post.user_id != self.user.key().id():
            self.redirect("/")

        post.delete()
        time.sleep(0.5)
        self.redirect('/')

# Handle comment creation
class NewComment(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')

        if post_id and content:
            c = Comment(parent=blog_key(), post_id=post_id, content=content,
                        author_id=self.user.key().id())
            c.put()

        self.redirect('/blog/%s' % str(post_id))

# Handle comment edit
class EditComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("editcomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect("/blog")

        content = self.request.get('content')

        if content:
            comment.content = content

            comment.put()
            self.redirect('/blog/%s' % str(comment.post_id))
        else:
            error = "content, please!"
            self.render("editcomment.html", comment=comment,
                        error=error)

# Handle comment deletion
class DeleteComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("deletecomment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect("/blog")

        comment.delete()
        time.sleep(0.5)
        self.redirect('/blog/%s' % str(comment.post_id))

# Handle the functionality of liking a post
class Like(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid != item.author_id and uid not in item.liked:
                item.liked.append(uid)
                item.put()
                time.sleep(0.5)

            if self.request.get('permalink') == 'True':
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog')

        else:
            self.redirect("/login")


# Handle the functionality of disliking a post
class Dislike(BlogHandler):
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            uid = self.user.key().id()
            if uid in item.liked:
                item.liked.remove(uid)
                item.put()
                time.sleep(0.5)

            if self.request.get('permalink') == 'True':
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.redirect('/blog')
        else:
            self.redirect("/login")


class Signup(BlogHandler):
    def get(self):
        print("llego al GET SignUp")
        self.render("signup-form.html")

    def post(self):
        print("llego al POST SignUp")

        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                    email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            print(self.password)
            print(self.verify)
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if have_error:
            print(params)
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            print(msg)
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            print("Registered")

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        print("llego")
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            print(msg)
            self.render('login-form.html', error=msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


## End Controllers


## ROUTER
app = webapp2.WSGIApplication([
    ('/?', BlogFront),
    ('/posts/([0-9]+)/delete', DeletePost),
    ('/posts/([0-9]+)/edit', EditPost),
    ('/posts/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout)
],
    debug=True)
