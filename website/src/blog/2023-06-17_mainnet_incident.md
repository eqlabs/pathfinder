# Mainnet outage post-mortem 

###### Posted on 26 June 2023

On Saturday, 17 June 2023, 18h05 UTC, Pathfinder nodes stopped syncing on mainnet causing an ecosystem wide outage. The cause was a disagreement between Pathfinder and the sequencer about a class hash. A fix was published the following morning at 08h30 UTC.

### Synopsis

The issue was first reported an hour after it occurred by Francesco (Apibara). As it involved a hash it made identifying the cause difficult. This was compounded by the timing - late Saturday night made it more complicated to get the right people involved. In addition, given that this was our first major incident, we didn't have a well-established protocol on how to handle the situation. This caused the issue to be under-communicated and delayed our response time.

Nine hours after the incident started, Jonathan Lei (starknet-rs) correctly identified the cause. A fix was submitted and merged three hours later, followed by a Pathfinder release two hours later. Two hours after that most of the ecosystem was upgraded and back in sync.

### Root cause of the issue

Pathfinder failed to sync block `84 448` on mainnet, with the following error:

```
WARN L2 sync process terminated with: Handling newly declared classes for block BlockNumber(84448)

Caused by:
    0: Downloading class 0x00801AD5DC7C995ADDF7FBCE1C4C74413586ACB44F9FF44BA903A08A6153FA80
    1: Class hash mismatch, 0x05294AB04A4BDFAEBBAE72688888D465AA4C5FD232D979A61AF1217215E1455A instead of 0x00801AD5DC7C995ADDF7FBCE1C4C74413586ACB44F9FF44BA903A08A6153FA80
```

Interpretation: a class with hash `0x00801AD5DC7C995ADDF7FBCE1C4C74413586ACB44F9FF44BA903A08A6153FA80` was declared but hash verification failed, causing the node to reject the block.

This is a Cairo 0 class, which made this incident all the more confusing. The code in question had been running untouched and problem free for over a year.

The culprit turned out to be JSON's flexibility with string encoding. A Cairo 0 class hash depends on its JSON artifact and JSON supports a variety of different string encoding formats. JSON libraries are therefore free to choose any of these formats when encoding an object. Unfortunately, the libraries used by Pathfinder and the sequencer use different encodings.

But then how did this ever work? It turns out most string encodings produce identical results for pure ASCII strings. The failing class was simply the first Cairo 0 class to include non-ASCII characters - in this case as part of the text for an error message. This caused the final encoded bytes to differ, resulting in a different hash.

### Resolution

The [fix PR](https://github.com/eqlabs/pathfinder/pull/1142) takes any non-ASCII characters and re-encodes them to match the formatting used by the sequencer. 

The PR was merged and Pathfinder v0.6.1 was released. The fix was also backported to create v0.5.7 for users who had not yet upgraded to v0.6.

### What went wrong

Bugs are a part of software and while we can follow best practices to reduce the number and severity of bugs, we can never fully eliminate them. In light of this, one should also have procedures in place to minimize the impact of bugs that do slip through. Our procedure was lacking - we could, and should have, done much better here.

We need much better system monitoring. Ideally an alert should have warned us 10 minutes in; instead we got lucky that an attentive user notified us only one hour later.

We also need better communication procedures. We managed to reach a Starkware engineer but clearly failed to communicate the severity of the issue. This meant people that could have helped were unaware of the issue until the next morning. Communication with the rest of the ecosystem was also limited due to the lack of properly defined communication channels and responsibilities.

It also highlights the lack of node diversity currently within Starknet. Having multiple node implementations divides the risk as different implementations are unlikely to share the same bug. Fortunately Starknet has a growing list of strong node implementations with Juno and Papyrus which will reduce this weakness in the future.

### Improvements

Mistakes are opportunities to learn and here are some of the lessons we have taken.

Improve our monitoring, especially around mainnet. This includes automatically notifying the relevant people.

Have a clear line of communication for emergency situations and have a response team on stand-by 24/7. Combined, these enable us to rapidly gather the people required to resolve the situation asap.

Establish a playbook for those providing support - these are stressful situations and it can be difficult to make decisions in the moment. We should know our roles and responsibilities. The more we can plan in advance the less we have to distract us during the crisis.

Know who is responsible for communicating with the ecosystem. This ties into the above point, but we want to emphasize that we are aware that this was a problem and are taking steps to address it.

Reduce the time taken from fix to release. Collectively, the release build time and time to regain sync took ~4 hours. This was compounded by the fact that two releases were required. Pathfinder will take steps to reduce its release build times. The sync times will be dramatically reduced once p2p support lands.

### Timeline

All times given are in UTC.

```
2023-06-17 18:05 Block `84 448` is created, Pathfinder nodes start failing
2023-06-17 19:10 Issue reported by Francesco via Telegram DM
2023-06-17 19:20 Test case replicating the failure created
2023-06-17 19:22 Issue raised with Starkware, at this point severity still unclear
2023-06-17 20:10 Reach out to others in the ecosystem for help, notably Jonathan Lei
2023-06-17 20:30 Follow potential leads given by Starkware engineers, unfortunately without success
2023-06-18 03:00 Jonathan Lei determines the root cause
2023-06-18 05:23 Jonathan Lei PR submitted with fix
2023-06-18 06:00 PR merged
2023-06-18 06:05 Pathfinder release build v0.5.7 initiated 
2023-06-18 06:55 Pathfinder release build v0.5.7 completed 
2023-06-18 07:00 Pathfinder release build v0.6.1 initiated 
2023-06-18 08:30 Pathfinder release build v0.6.1 completed 
2023-06-18 08:30 API services start upgrading
2023-06-18 10:30 API services upgraded
2023-06-18 11:30 API services back in sync and online
2023-06-18 11:30 incident over
```