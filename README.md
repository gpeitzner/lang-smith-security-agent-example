# Building a Security Agent with LangSmith

An important software company has been dealing with some availability issues lately. They have an API that is widely used by external partners. The API has only one endpoint that processes important data and sends it back to the clients. The API has middleware that authenticates and authorizes the client; this process consumes a certain amount of compute cycles since the whitelist is stored using a plain-text file. So, every time a client wants to consume the API, the middleware needs to read the file and verify if the IP of the client is in the whitelist. The problem they are facing is that some malicious actors have been trying to breach this middleware, and to do this, they have been using brute-force attacks, downgrading the performance of the API. They provided us with a link where we can find the code of the API, and the folder structure looks like this:

```bash

```
