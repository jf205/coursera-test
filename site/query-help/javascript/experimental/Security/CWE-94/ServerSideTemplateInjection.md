# Server Side Template Injection
Server-Side Template Injection vulnerabilities occur when user input is embedded in a template in an unsafe manner allowing attackers to access the template context and run arbitrary code on the application server.


## Recommendation
Avoid including user input in any expression or template which may be dynamically rendered. If user input must be included, use context-specific escaping before including it or run the rendering engine with sandbox options.


## Example
The following example shows a page being rendered with user input allowing attackers to access the template context and run arbitrary code on the application server. The Pug template engine (and other template engines) provides an interpolation feature - insertion of variable values into a string of some kind. For example, `Hello #{user.username}!`, could be used for printing a username from a scoped variable user, but the `user.username` expression will be executed as JavaScript. Unsafe injection of user input in a template therefore allows an attacker to inject arbitrary JavaScript code. For example, a payload of `#{global.process.exit(1)}` will cause the below server to crash.


```javascript
const express = require('express')
var bodyParser = require('body-parser');
const app = express()
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//Dependent of Templating engine
var jade = require('pug');
const port = 5061

function getHTML(input) {
    var template = `
doctype
html
head
    title= 'Hello world'
body
    form(action='/' method='post')
        label(for='name') Name:
            input#name.form-control(type='text', placeholder='' name='name')
        button.btn.btn-primary(type='submit') Submit
    p Hello `+ input
    var fn = jade.compile(template);
    var html = fn();
    console.log(html);
    return html;
}

app.post('/', (request, response) => {
    var input = request.param('name', "")
    var html = getHTML(input)
    response.send(html);
})

app.listen(port, () => { console.log(`server is listening on ${port}`) })

```

## Example
The example below provides an example of how to use a template engine without any risk of Server-Side Template Injection. Instead of concatenating user input onto the template, the template uses a placeholder and safely inserts the user input.


```javascript
const express = require('express')
var bodyParser = require('body-parser');
const app = express()
app.use(bodyParser.urlencoded({ extended: true }));

//Dependent of Templating engine
var jade = require('pug');
const port = 5061

function getHTML(input) {
    var template = `
doctype
html
head
    title= 'Hello world'
body
    form(action='/' method='post')
        label(for='name') Name:
            input#name.form-control(type='text', placeholder='' name='name')
        button.btn.btn-primary(type='submit') Submit
    p Hello #{username}`
    var fn = jade.compile(template);
    var html = fn({username: input});
    console.log(html);
    return html;
}

app.post('/', (request, response) => {
    var input = request.param('name', "")
    var html = getHTML(input)
    response.send(html);
})

app.listen(port, () => { console.log(`server is listening on ${port}`) })

```

## References
* OWASP: [Server Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection).
* PortSwigger Research Blog: [Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection).
* Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
