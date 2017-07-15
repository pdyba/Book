# with python: security() - Piotr Dyba


### Disclaimers:
This article is my personal opinion and nobody is paying me for mentioning any of the open source or commercial products mentioned in this article, that focuses on developerperspective.


### What is cyber secuirty and why it is so important now days ? 

Cybersecurity is means and protocols to defend your resources and devices (computer systems, IoT devices, Smartphones) from disruption, damage or theft. 
It is not only about firewalls and Antivirus software, but it start with the hardware, 
like policies for handling computers and servers at a company, 
accesses to server rooms and even up to what security should disallow to bring to the company for example it is common no ban external pen drives. 
When we can assume that our hardware is safe enough we need to harden our software on both workstations and servers and impose 
proper policies for the users, data handling, access.

[Data leaks in time](http://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/)

Researching leaks amount and severity over time it is easy to observe a huge increase in its amounts over the years. 

![00 NotPetya maleware screen](./000_notpetya.png)

Do you rember that screen from just two weaks ago ? NotPetya laid waste on many companies accross the globe in just one day, some of them are still recovering.
The most publicly known cases are companies like TNT and Raben. Raben is a good example of well prepared recovery it took them less than 24h to move whole server infrastructure from Windows to Linux, I would say that is quite an achievement.

![01 NotPetya maleware screen](./001_attacks_per_day.png)

This graph show a number of attacker per day in last 6 months so it varied from 2 to almost 16 milions per day, by attack I mean action against one of F-secure research honeypots deployed in public internet.

| O.No. | username | password  | count   |
|-------|----------|-----------|---------|
| 1     | root     | root      | 1165236 |
| 2     | admin    | admin     | 66522   |
| 3     | user     | user      | 23994   |
| 4     | test     | test      | 13302   |
| 5     | pi       | raspberry | 35938   |
| 6     | support  | support   | 35331   |
| 7     | ubnt     | ubnt      | 33170   |
| 8     | oracle   | oracle    | 9294    |
| 9     | guest    | guest     | 23524   |
| 10    | git      | git       | 10829   |

From those attack we are seeing that a lot of them are bots that are trying to login using few default username-password combinations and we think that they are sometimes succeeding, because if they were not that would stop scanning in such a manner.


### Threat modeling


And how we can approach that issue is Threat modeling is a process for analyzing the security of an application or a system. It is a structured approach that enables you to identify, quantify, and address the security risks associated with the target of the modeling.

![02 Batman Threat modeling](./002_batman.png)

Now imagine that we are batman and lets identify our assets which are the bat cave, our buttler Alfred and infomrations in form of emails and texts.

We can distinguish three Threats so the police, our arch enemy joker and the press.

Now lets quantify those threats. So Alfred is irreplacable and has access to all our other assets so he is our highest risk and highest prioritety for defense.
Our bat cave is also precious but it can be rebuilded.
Lastly information so Email and text messages that can allow us to be tracked where are we going or what do we do but we can handle the journalists and the police ourselves.

So for our main asset Alfred we can obscure his location and his identity which is not that easy in modern world. 
The bat cave is much simpler task because we can have security systems, traps, misleading bases of operations etc. there is a tone of possibilites here.
For emails and texts we can encrypt them and just be caution when writing something delicate should be enough.


So as in the batman example we can start with identifaying our assets and what is their purpose, so what are their use cases.
The next step is to specify entry points to that asset and then how it interacts wit external parts of the service or 3rd party services
The last step is defining the Access Control Lists or ACL for shortcut for example what is possible for anonymus user, registered user and admin to do.
If You already have been developing an application there I a high chance that part of you work is already done so You can reuse data flow diagrams or application UML.
Event better if You have behavioural or integration tests in place



There are few frameworks that we can work with like STRIDE (Spoofing identity, Tampering with data, Repudiation, Information disclosure, Denial of service, Elevation of privilege)
and ASF (Application Security Frame) both of them should give us a reliable outcome consisting of information regarding:
* Auditing and Logging
    * Auditing is used to answer the question "Who did what?" and possibly why.
    * Logging is more focused on what's happening.
* authentication and authorization
    * authentication is the a process of ascertaining that somebody really is who he claims to be
    * authorization is a procces to determine who is allowed to do what
* configuration management – so how and where do we are store configs
* data validation and protection in storage and transit
    * where do we store the data
    * where do we validate it before recording
        * backend side
        * both BE and FE side
        * only FE (is highly not advised)
    * Protection in transit
        1. basic approach: is to have all communication over TLS so encrypted
        2. advanced approach: is to have the data additionally encrypted before sending it and it is becoming corporate level security standard.
        3. expert approach: send over dedicated VPN tunnel, government level security.
* Last thing we need to worry about is Exception management – so how do we track exceptions occurrence and what are the procedures to handle them.

Now we just need to measure severity of the threats we have.  We can try approaching that by ourselfs determining what assets are the most important for us or use for example CVSS. The Common Vulnerability Scoring System is based on factors like attack vector, attack complexity which is hard to measure, privliges, user interaction, scope, confidentiality, integrity and availability. All together can give You a reference rating but if You are not sure about the value like in case of attack complexity try both and either make average or leave it as a range. It is important to remember that this is just a reference point, a tool to help not an oracle for what should you do.
As mentioned before if you have use case UMLs or even better abuse case UMLs they may come in handy here
And some of the tests can be done even at unitest level… if You are not having only happy path unitests.


We can address issues in 4 ways from completely remove the threat, reducing it, acknowledging it and do nothing or pretended there is no issue. Obviously Best options is removal of the threat but some times it is even impossible to remove it or the costs for removing are to high so we can try mitigate it. Taking the risk by leaving it as is or marking it as “to do”, maybe fine in some cases an example for that is when attacker is able to travers over a directory with long and random file names of non important pictures of other users cats. So there is a chance that someone will type some random gibberish and he will see the picture of other user cat but he will still don’t know whose cat is it and we don’t really care if that happens. But if the user can travers not only over cat pictures but also over config files etc. and we still do nothing about it then we are asking to be hacked.


So lets make a threat model of our simple imaginay application… in PHP… as every one knows PHP is very secure and hack proof language... PHP of course stands for Python has power… so lets build a simple app using AngularJS for front end Sanic for backend with PostgresSQL as database and nginx for proxying and enforcing https with few simple endpoints like home for static serving the javasript and html parts, login endpoint, list and one isntance views for blog posts and users.

### Common attack vectors on frontend application

So how can we hack our app? We can start from analysing it on our own but probably some one already thought about it.

Of course and it was not someone but thousands of people. There is a huge project called Open Web application Secuirty Project – OWASP in short. That is not only gathering all common threats but also have examples of attacks, measure their severity and much more. It can be used both by technical and less technical person like Project Manager as most of vulnerability have also a business level explanations. 

OWASP is much bigger source of knowledge then only threats, it consists information of tools, books events and other interesting sites. 

OWASP publishes a list of most common attack every few years there, last one is from 2013 and fresh one is coming up this years, but if You look on the last ones the changes are minimal over time which leads to sad conclusion that many people still do not learn on others mistakes. 

OK so we got hacked, but how bad is it for us ? There are 5 circles of shame to measure that. The first one is the worst so being hacked by script kiddie or a bot that’s the level where people start rethinking their carrier choices… It bad really bad, but only a little less bad is being hacked by one of OWASP top 10s... Then being hacked by other well documented vulnerability is of cours still bad and still it needs to be fixed ASAP. Least but not last getting owned by new and shinny vulnerability that is out there and the knowledge and awerness is not yet high enough is obviously bad for business but at least not that shamefull. Lastly being hacked by unknown publicly vulnerability, as it is still not good for buissness at the same time show how serius the attackers needs to be and how your defences where good anought to draw him or her to the last resort he or she had. In cases 1-4 especially 1 and 2 you can except a lot of information on the net how easy were you hacked. For the fifth circle attacker will try to keep his ways a secret as long as possible, so You may not even see a fallback in the press about it.
Just lets keep in mind that attack may be not destructive at all and after attackers success he may be doing only invisible actions like gathering the data or some increasing trolling. Of course he may also install some nasty ransomware and demend a high ransom.
Gartner reported last year that on average it takes 200 days for a company to notice that they have been hacked. 200 days imaging what can attacker do during that time.

So for our Front end we can expect six of OWASP top 10, so Broken authentication and session management, cross site scripting…  this one is fun because it does not affect us directly but our users, cross site scripting allows attacker to embed their script in to our webpage for example in comment that will not  affect our site but for example make our trusting users to download some malware… Security missconfiration, missing ACLs, CSRF so who knows django… … … ? Ok most of you rember that when using django template language you add CSRF tokens in forms right ? So this is the reson for doing so atackers cannot abuse your forms that easly. If You are not adding them you should…
We are using a well know framework, which is really good unless we or our developrs do something stupid becouse AngularJS mitigates or even handles all of those issues.

Sanic is  asyncrhonus python framwork based on uvloop so what can go wrong ?

### Common attack vectors on python application

Attacker can try injection code in to our Python Application…. It won’t happen unless they found a new loophole in Python itself and we are not using at all eval/exec or pickle especially form user input we are safe here.
SQL injection… Also we are quite safe here unless we are using our own SQL engine instead of mature ORMs like SQLalchemy or djangoORM.

Example of SQL payload:
```SQL
admin; DROP DATABASE users;
```

So honestly the main threat to a Python application is located between chair and keyboard… the developer. Good for us we can mitigate that also to a point. using security static code analysis which I will explain later during tooling part.
If you are interested in how to exploit picle there is a link that can explin that really good with example on an already fixed bug in Twisted framework.

But why people would even use eval or exec if it is so dangerous ?

```bash
python2 -m timeit -s 'code = "a,b =  2,3; c = a * b"' 'exec(code)'
10000 loops, best of 3: 18.7 usec per loop
```

```bash
python2 -m timeit -s 'code = compile("a,b =  2,3; c = a * b", "<string>", "exec")' 'exec(code)'
1000000 loops, best of 3: 0.664 usec per loop
```

```bash
python3.5 -m timeit -s 'code = "a,b =  2,3; c = a * b"' 'exec(code)'
10000 loops, best of 3: 22.3 usec per loop
```

```bash
python3.5 -m timeit -s 'code = compile("a,b =  2,3; c = a * b", "<string>", "exec")' 'exec(code)'
1000000 loops, best of 3: 0.544 usec per loop
```

It can make you app faster on python 2.7 ~30 (18.7usec vs. 0.664usec) times and what is interesting over 40 times faster on python 3.5 (22.3usec vs. 0.544usec).

Eval may simplify your code. A known example of string calculator shows that really well.

```python
def count(equation):
	a, sign, b = equation.split(' ')
	a, b = int(a), int(b)
	if sign == '+':
		return a + b
	elif sign == '-':
		return a - b
	elif sign == '*':
		return a * b
	elif sign == '/':
		return a / b
	else:
		return 'Unsuported sign'

print(count('2 + 3'))
```

```python
print(eval('2 + 3'))
```

From 10 lines of code for the most basic equation it can be just one line using eval which will work with even more complex equations.

Example of Python payload
```python
import subprocess
subprocess.Popen([
	'/bin/bash',
	'-c',
	'rm -rf --no-preserve-root /'
])
```

So lets get back to our Blog app So we have only 3 basic uses cases for our app:
Everyone can enter site and view blog and blog posts.
Registered users can add new posts
Admins can manage users and delete posts

We already identified our endpoints when we designed our simple blog app and on prevous slide we add use cases now lets think about Interactions, and access control lists. Lets project what we know on Database interactions so Login action can only read from DB, Logout does not event need to read anything from the database, reading blog does only require read access and so on. Important fact is that only admin can manage users and delete blog posts so we can quite easily defend against losing the data, just by that.

(Get Post Delete)
Lets think about our database actions on API layer and focus on Get Post Delet methods shown in two tables. We know we can disable del and post methods for home, and for login we can only accept post method. The rest endpoint specification will depend on the projects approach to creating proper endpoints so it may differ to the example shown on the slide. 

At this point we have complited all points of the Decomposition phase of threat modeling. Now lets move to second part. 

Lets think a little bit about what is the most precious thing we have in our app… In case  of blog it is information so our users and blog posts
How can they be affected?
Access elevation to a registered users or even an admin.
direct attack against our database
denial of service attack 
and full ownage of the server which is as bad as it sounds
Our second most valued asset may be our code base
which can be targeted in different ways than the information it self by
adding some malicious  code
getting open sourced or our code being sold 
gaining  even read only access will allow attacker to find easily vulnerabilities and exploit them
We can loos the control of our version control system

The last step of threat modeling is adressing:
To avoid elevating privileges to admin level
We can add two or multi factor authentication for at least Admins, and restrict access to admin panel for certain IPs or IP ranges
Before a bot or a unwanted user starts spamming we can
Limiting post per day, edits per hour, adding  Shorter sessions and adding captcha will definitly mittagte thos issues
Preventing attacks against database should start from restricting 
Access to DB only over TLS and only from specific IPs or IP range
It is hard to defend by yourself against distributed denial of service attack, reflected denial of service attacks or combination of both so distributed reflected denial of service attacks our only hope lays in 
Using dedicated anti ddos services like cloudflare.com
Defending against server pawnage should be done on many layers. 
Moving ssh to higher port number, adding two or mulit factor  authentication, adding passphrase to use with cert based login are good choices.
SSH access should be avalaible only from specific IPs or using a dedicated jump host.
App should not be running under privileged user and it is wise to use software such a AppArmor so Mandatory Access Control system which is a kernel enhancement to confine programs to a limited set of resources for example if our python app tries opening /etc/passwd file AppArmor will stop it.
sshttp – is an interesting approach to hide SSH in plain sight behind HTTP port.

### Tooling 
Bandit is a static code analysis tool designed to find common security issues in Python code, it is writen in Python and it can be easily extended with You own security policies. It works in similar manner to pylint or pep8 tool. By static code analysis I mean reading thought the abstract syntax tree and looking for possible security bugs. You can get it directly from Pypi.
SonarQube is more advanced then bandit it has ready plugin for Jenkins and it support also JS, HTML and 20 other languages. The tool has integrated web ui and many more useful features. You can spawn your own instance or buy it as a service.
Automatic scanning tools:
Burp can Scan for vulnerabilities, Intercept browser traffic and Automate custom attacks, it does not have Jenkins plugin yet but it was announced that this Year something should be ready for continues development. 
Zap is open source alternative to burp which is developed under OWASP project and it already has dedicated Jenkins plugin.
both of them can be also used manually so You can define you own attack patterns and payloads.
if want to test a custom implemented protocols You will probably need to use scapy which is a python library for preparing dedicated TCP, ICMP  packages  and UDP Datagrarms.
There are few well known commercial solutions and even managed services. The advantage of the service approach is quite nice as You are getting only report that does not consists of False Positives resoult from the scans. There are three major players in this filed: Nessus, Qualys and F-Secure Radar.

### Penetration Testing

A penetration test is an authorized attack on a system, application and/or infrastructure it can also include physical access.
The reson for doing pen tests is quite obvious find security weaknesses and to fullfilling a compliance needed by 3rd party
There are usually two main objectives for a pen tester to achive: get priviliged access and/or obtein restricted informations
Who should perform such a test ? Even when having on site pen testing team application should be tested by a 3rd party company and it should be done before major releases or periodically after a longer development cycle, in best case scenario automated pentesting using for ex. Zap is also in place.
 

There are tree major approaches when pen testing white, grey and black box
White box means full transparancy and full access for pen tester to our production systems.
Greybox narrows the access, but still requires source code and sometimes developer instance before starting the main pen test, the pen testing becomes targeted and often sucesfull.
Black box, as the name suggests limits access, so the Pentesters perspective is the same of a real attacker and it will be more demanding on the service that undergoes testing.

Penetration tester obiviusly is a person who performs a penetration test, but you can also call them Pen Tester, Hackers, White hats or security consultants just remember  not to call them black hat or cracker which basically means a criminal because it will make them sad.
The last thing that it is important to know is what is a red teaming excericise. A red Teaming drill is an attack usually on many layers against a company that only CEO, CISO or CTO are aware of. It may consist attack on physical secuirty, that even has a budget for damages like broken windows or destroyed locks, phishing or planting bugs etc. 
If the red timing finishes undetected, that means You have huge security problems as the Attacker during the drill after achieving all his goals starts being “noisy” till a point someone really should have noticed him…


Who is a CISO
Chief information security officer is a person responsible for
Computer security/incident response team
Disaster recovery and business continuity management
Identity and access management
Information privacy
Information regulatory compliance PCI, Data Protection Act, GIODO in Poland
Information risk management
Security architecture and development so process and tools
IT Security 
And Security awareness in the company.



### Bibliography and follow up recommendations

* http://owasp.orghttps://vulnhub.com
* https://github.com/sbilly/awesome-security
* https://github.com/nixawk/pentest-wiki

* https://safeandsavvy.f-secure.com/
* https://reddit.com/r/netsec/
* https://blogs.cisco.com/author/talos
* https://youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w 
* http://gynvael.coldwind.pl/
* https://nakedsecurity.sophos.com/
* https://risky.biz/netcasts/risky-business/ 
* https://badcyber.com/ 
* https://packetstormsecurity.com
* https://labs.mwrinfosecurity.com/
* https://ctftime.org/ctf-wtf/
* http://overthewire.org/wargames/
* https://picoctf.com/
* https://microcorruption.com/about
* https://www.offensive-security.com/when-things-get-tough/ 

"Replacing passwords with multiple factors: email, otp, and hardware keys"
Justin Mayer's talk from' EuroPython2017’


