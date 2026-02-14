# Building a Security Agent with LangSmith

An important software company has been dealing with some availability issues lately. They have an API that is widely used by external partners. The API has only one endpoint that processes important data and sends it back to the clients. The API has middleware that authenticates and authorizes the client; this process consumes a certain amount of compute cycles since the whitelist is stored using a plain-text file. So, every time a client wants to consume the API, the middleware needs to read the file and verify if the IP of the client is in the whitelist. The problem they are facing is that some malicious actors have been trying to breach this middleware, and to do this, they have been using brute-force attacks, downgrading the performance of the API. They provided us with a [link](https://github.com/gpeitzner/lang-smith-security-agent-example/tree/8900add2e5c1484e4a344c71ee2a4cf1170580b8/src/start) where we can find the code of the API to get familiar with the app, and the folder structure looks like this:

```bash
/src
- evil.sh #a script that simulates the brute-force attack
- index.js #the main file of the API
- package-lock.json #npm lock file
- package.json #npm package file
- whitelist.json #a file that contains the list of whitelisted IPs
```

We proceed by installing the `npm` dependencies:

```bash
npm install
```

Then we start the application:

```bash
npm start
```

The application generates the following output:

```bash
> api@1.0.0 start
> node index.js

API listening at http://localhost:3000
```

We are ready to execute the brute-force attack script:

```bash
chmod +x ./evil.sh && ./evil.sh
```

After we have executed the test script for one minute, we can see that the application has generated a log file called `./login.log`, and the content looks like this:

```txt
2026-02-14T22:02:59.295Z - Login attempt from 192.256.1.4 - SUCCESS
2026-02-14T22:02:59.832Z - Login attempt from 192.256.1.6 - FAILED
2026-02-14T22:03:00.354Z - Login attempt from 192.256.1.3 - SUCCESS
2026-02-14T22:03:00.886Z - Login attempt from 192.256.1.9 - FAILED
2026-02-14T22:03:01.418Z - Login attempt from 192.256.1.9 - FAILED
2026-02-14T22:03:01.947Z - Login attempt from 192.256.1.7 - FAILED
2026-02-14T22:03:02.479Z - Login attempt from 192.256.1.8 - FAILED
2026-02-14T22:03:03.010Z - Login attempt from 192.256.1.9 - FAILED
2026-02-14T22:03:03.539Z - Login attempt from 192.256.1.1 - SUCCESS
2026-02-14T22:03:04.070Z - Login attempt from 192.256.1.10 - FAILED
```

Now that we have a full understanding of the API, the software company has given us the responsibility of implementing a middleware and a security agent. The middleware will have the responsibility of blocking brute-force attacks by reading a blocklist stored on a Redis instance. The Redis database will be populated by a security agent that will read the `./login.log` file and identify malicious IP clients every minute. The software company hasn't provided us with access to the Redis database since its security policies are too restrictive, so we use Docker for development purposes:

```bash
docker run -d --name my-redis -p 6379:6379 redis:latest
```
