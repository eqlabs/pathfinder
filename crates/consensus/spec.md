#### Tendermint Overview and Introduction

Tendermint is a PoS protocol that proceeds in heights and rounds. The protocol
is fully resistant to up to 1/3 of the total stake being malicious. The protocol starts
at height 0, and whenever consensus in achieved on a block, the height increments
by 1. At each height, the protocol might require multiple rounds, and each round is
split into three stages: proposal, prevote, and precommit. (These are made more concrete
later.) Generally, each round and each stage take a predefined amount of time.
Under happy conditions, a round will result in consensus.
Under less happy conditions, a round
might not reach consensus, in which case the next round will have more time dedicated
to it in order to offset potential bad network conditions.

During each round, a _leader_ is elected (how will be explained later).
This leader node is also referred to as the
_proposer_, because it has the job of proposing the new block for that height. The other
participating nodes are referred to as _voters_. The voters might be formed from a _committee_,
i.e. only a subset of the network that vote on the block and not the entire network.
(However, the spec ignores this, because it doesn't really change anything in the protocol.)
The voters initially cast a prevote (a.k.a. stage 1 vote) if they receive a valid block.
Upon collecting a 2/3 majority of prevotes, the voters then cast a precommit (a.k.a. stage 2 vote)
for the block. Upon collecting a 2/3 majority of precommits, the node assumes that consensus has been
achieved and moves on to the next block.

A potential issue arises due to network congestion where during a round a 2/3 majority
of precommits is globally achieved, but fails to be globally gossiped before the
start of the next round. In that case the nodes might move on to voting for a different
block, while the last block is actually confirmed. This can lead to a fork. To avoid this,
Tendermint employs a locking strategy: put simply, once a node has precommitted to a block, it locks
on that block. From there on, it will always propose that block and only accept proposals
for that block. Those are the broad strokes, the details are slightly more involved
and made concrete in the spec below.

Leader (and committee) election is a randomized process (because
if the process is predictable over a long period of time, it can be abused). Starknet
solves this issue by reusing L1 randomness, a.k.a. the [RANDAO](https://github.com/randao/randao).
Elections are proportional to stake, meaning that if a node has higher stake,
it is more likely to be elected as a leader (or committee member).
Starknet manages all stake on L1.

#### Tendermint Messages

The protocol supports the following signed messages:
- `PROPOSAL`, denoted as `{PROPOSAL, height, round, block, validRound}`, is used by the
  proposer node for the current height and round to propose a block. The `height` field
  is the current height as seen by the proposer node, `round` is the current round, `block`
  is the block being proposed by the node, and `validRound` is the `validRound_p`
  variable of the proposer node, defined below.
- `PREVOTE`, denoted as `{PREVOTE, height, round, block_hash}`, is used by voters to
  cast a prevote (stage 1 vote) for the given `block_hash`
  at the given height and round of the protocol. `block_hash` can be nil, meaning no block.
- `PRECOMMIT`, denoted as `{PRECOMMIT, height, round, block_hash}`, is used by voters to
  cast a precommit (stage 2 vote) for the given `block_hash`
  at the given height and round of the protocol. `block_hash` can be nil, meaning no block.

#### Annotated Tendermint Spec

Define initial values for variables local to our node (a.k.a. the _current node_). These variables
end with `_p` (meaning current _process_). The "current node" is referred
to as the value `p` in the pseudocode.
```
1: Initialization:
```
---
Current protocol height (i.e. blockchain height) and round.
```
2:   h_p := 0
3:   round_p := 0
```
---
Current protocol step as seen by this node.
- `propose` means that the node is waiting for a proposal and has not yet
  cast a prevote (i.e. sent a `PREVOTE` message) this round.
- `prevote` means that the node has cast a prevote this round and is now
  waiting for a majority prevote from the network so it can precommit
  (i.e. send the `PRECOMMIT` message).
- `precommit` means that the node has precommitted. Now the only thing left
  is to wait a bit for as many nodes to collect as many precommits as possible
  before starting consensus on the next block in the blockchain.
```
4:   step_p (one of propose, prevote, precommit) := propose
```
---
The blocks agreed on by consensus as seen by this node. This is a map from
protocol height to block value.
```
5:   decision_p [] := nil
```
---
The last block that was precommitted by this node (i.e. the last block for which a `PRECOMMIT`
message was sent by this node), and the round it was precommitted at (i.e. the round
in which the `PRECOMMIT` message was sent).
```
6:   lockedValue_p := nil
7:   lockedRound_p := −1
```
---
The last block with a majority vote seen by this node and the round when it was seen.
```
8:   validValue_p := nil
9:   validRound_p := −1
```
---
Define a `StartRound(r)` function to be executed at the start of each round
`r` by the node. Initially execute it for round 0. The `proposer(h, r)` function
returns the proposer for height `h` at round `r`. In our case, this value is calculated
based on random numbers from L1, a.k.a. the [RANDAO](https://github.com/randao/randao).
If the current node is the proposer, it will either propose the last known valid value
(i.e. the last valid block that it has seen with a majority prevote, see line 42), or
it will create a brand new block from transactions in its mempool
if it hasn't seen a valid value yet (the `getValue` function builds a block from mempool transactions).
If the current node is not the proposer, it will instead schedule a timeout to run the
`scheduleOnTimeoutPropose` function, which is defined later (line 57).

Timeouts are always a function of the current round, as seen by `timeoutPropose(round_p)` in the
code. The more rounds there are, the longer the timeouts should get, e.g.
`timeout(r) = initialTimeout + r * delta`. This is so that the protocol can proceed even
in cases where the network is being slow or congested, by allowing more round time for each
node to send and receive messages.
```
10: upon start do StartRound(0)
11: Function StartRound(round) :
12:   round_p = round
13:   step_p = propose
14:   if proposer(h_p, round_p) = p then
15:     if validValue_p != nil then
16:       proposal = validValue_p
17:     else
18:       proposal = getValue()
19:     broadcast {PROPOSAL, h_p, round_p, proposal, validRound_p}
20:   else
21:     scheduleOnTimeoutPropose(h_p , round_p) to be executed after timeoutPropose(round_p)
```
---
Handle the case where during the propose step, a `PROPOSAL` message is received with the `validRound`
field set to `-1` (the initial value defined above). This means the proposer is not aware of
any earlier valid blocks with a majority prevote.
If the `height` or `round` fields in the message are incorrect (i.e. different than `h_p` and `r_p`),
ignore the message. If the node sending the message is not the correct proposer for this height and round,
ignore the message.

The current node will cast a prevote for this proposal only if the block is valid (`valid(v)` in the code) and either
the current node has not precommitted to any block (i.e. `lockedRound_p` is `-1`), or it's precommitted
to the same block that is being proposed by this message (i.e. `lockedValue_p` is the same as the block being proposed).
Otherwise the node will prevote the `nil` value, meaning it is
rejecting the proposal and not voting for any block this round.
This means that the current node will never vote for a different block after precommitting to a specific block,
unless a block gets proposed with a more recent `validRound` value and a majority prevote. See also line 29 below.

The current round proceeds to the prevote step and `step_p` is updated.
```
22: upon {PROPOSAL, h_p , round_p, v, −1} from proposer(h_p, round_p) while step_p = propose do
23:   if valid(v) AND (lockedRound_p = −1 OR lockedValue_p = v) then
24:     broadcast {PREVOTE, h_p , round_p, id(v)}
25:   else
26:     broadcast {PREVOTE, h_p , round_p, nil}
27:   step_p = prevote
```
---
Handle the case where during the propose step, a proposal is received with the `validRound` field in the
half-open range `[0, round_p)`, and a majority of prevote messages are received for the corresponding `validRound` of the proposal.
Note that this condition may be triggered upon receipt of a `PROPOSAL` message (if the current node is already aware of a majority
prevote corresponding to the `validRound` of that proposal)
_or_ upon receipt of a `PREVOTE` message (if that prevote results in a majority).
This means that the proposer is aware of some earlier valid block with a majority vote,
for which the current node also has a majority vote.
(Notice that in the code, there is a common binding
`vr` between the `{PROPOSAL, ...}` and `{PREVOTE, ...}` messages - this means that the fourth field of `PROPOSAL` (i.e. the `validRound` field) and
the second field of `PREVOTE` (i.e. the `round` field) must be equal. Also note that this condition implies that
each node must keep track of all prevotes for all rounds during a specific protocol height, as well as the active
proposal for the current round.)

If the `height` or `round` fields in the `PROPOSAL` message are incorrect (i.e. different than `h_p` and `r_p`),
ignore the message. If the node sending the `PROPOSAL` message is not the correct proposer for this height and round,
ignore the message. If the `height` field in the `PREVOTE` message is incorrect (i.e. different than `h_p`), ignore
the message.

A prevote will be cast for the proposed block only if the block is valid and either the `lockedRound_p` value is
earlier than the `validRound` field of the proposal (meaning that the proposal is newer than the last
precommit of this node), or the current node has precommitted to the block being proposed
(i.e. `lockedValue_p` is the same as the block being proposed). Otherwise a nil prevote will be cast.
This means that the current node will never vote for a different block after precommitting to a specific block,
unless a block gets proposed with a more recent `validRound` value and a majority prevote. See also line 23 above.
Note that `id(v)` denotes the hash of block `v`.

The current round proceeds to the prevote step and `step_p` is updated.
```
28: upon {PROPOSAL, h_p, round_p, v, vr} from proposer(h_p, round_p)
    AND 2f + 1 {PREVOTE, h_p, vr, id(v)}
    while step_p = propose AND vr >= 0 AND vr < round_p do
29:   if valid(v) AND (lockedRound_p <= vr OR lockedValue_p = v) then
30:     broadcast {PREVOTE, h_p, round_p, id(v)}
31:   else
32:     broadcast {PREVOTE, h_p, round_p, nil}
33:   step_p = prevote
```
---
Upon receiving a majority prevote for the current height and round _for the first time in the round_,
schedule a timeout to run the `OnTimeoutPrevote` function (defined on line 61) with copies
of the current height and round values (`h_p` and `round_p`).
```
34: upon 2f + 1 {PREVOTE, h_p, round_p, ∗} while step_p = prevote for the first time do
35:   schedule OnTimeoutPrevote(h_p, round_p) to be executed after timeoutPrevote(round_p)
```
---
Handle the case where during the prevote or precommit steps, a proposal is received and a majority of prevote
messages are received for that proposal during the current round. (Once again this can be triggered by either
receiving a `PROPOSAL` or a `PREVOTE` message).

If the `height` or `round` fields in the `PROPOSAL` message are incorrect (i.e. different than `h_p` and `r_p`),
ignore the message. If the node sending the `PROPOSAL` message is not the correct proposer for this height and round,
ignore the message. If the block proposed by the `PROPOSAL` message is not valid, ignore the message. If the `height`
field in the `PREVOTE` message is incorrect (i.e. different than `h_p`), ignore the message.

This condition can only execute once per round (because the pseudocode states `for the first time`).

Update the `validValue_p` to the proposed block `v` and `validRound_p` to the current round `round_p`. Essentially,
this is because the current node has just witnessed a proposal with a majority vote in the current round, i.e.
this block is the latest majority-voted block that the node has seen thus far.

Additionally, if the current step is prevote, update the `lockedValue_p` and `lockedRound_p` values, cast a `PRECOMMIT`
for the current block, and advance to the `precommit` step.

This covers the happy path where a proposal succeeds in getting a majority prevote and proceeds to the precommit step.
```
36: upon {PROPOSAL, h_p, round_p, v, ∗} from proposer(h_p, round_p)
    AND 2f + 1 {PREVOTE, h_p, round_p, id(v)}
    while valid(v) AND step_p >= prevote for the first time do
37: if step_p = prevote then
38:   lockedValue_p = v
39:   lockedRound_p = round_p
40:   broadcast {PRECOMMIT, h_p, round_p, id(v)}
41:   step_p = precommit
42: validValue_p = v
43: validRound_p = round_p
```
---
Upon receiving a majority `nil` prevote for the current round during the prevote step,
immediately precommit to `nil` (meaning no block).
This means that if the majority seems to be voting for no block, the current node will immediately
also vote for no block. This is a safety measure.
Ignore `PREVOTE` messages if the height is not correct, i.e. if it's different than `h_p`.
```
44: upon 2f + 1 {PREVOTE, h_p, round_p, nil} while step_p = prevote do
45:   broadcast {PRECOMMIT, h_p, round_p, nil}
46:   step_p = precommit
```
---
Upon receiving a majority precommit for the first time in the round, schedule a timeout to
run the `OnTimeoutPrecommit` function (defined on line 65) with copies of the current height and round
values (`h_p` and `round_p`).
```
47: upon 2f + 1 {PRECOMMIT, h_p, roundp, ∗} for the first time do
48:   schedule OnTimeoutPrecommit(h_p, round_p) to be executed after timeoutPrecommit(round_p)
```
---
If the current node has a valid proposal with a majority precommit and has not achieved consensus
on the current height of the protocol yet, then the proposed block is the result of consensus. Move
on to the next height (i.e. next block) and reset the round to 0.
This is because a majority precommit always indicates that consensus has been achieved.
```
49: upon {PROPOSAL, h_p, r, v, ∗} from proposer(h_p, r) AND 2f + 1 {PRECOMMIT, h_p, r, id(v)} while decision_p[hp] = nil do
50: if valid(v) then
51:   decision_p[h_p] = v
52:   hp = hp + 1
53:   reset lockedRound_p , lockedValue_p, validRound_p and validValue_p to initial values and empty message log
54:   StartRound(0)
```
---
As soon as more than 1/3 of prevotes or precommits are received for a round higher than the
current round, immediately advance to that round. Note that the protocol assumes that
less than 1/3 of voters are malicious, hence a 1/3 minority can be trusted in this case.
(However, a 2/3 majority is always required to actually achieve consensus!)
```
55: upon f + 1 {∗, h_p, round, ∗, ∗} with round > round_p do
56: StartRound(round)
```
---
Define the proposal timeout function.
This function is only scheduled if the current node is not the proposer for this round.
See lines 21 and 14. It only runs if the current round has not advanced from the propose step for
the duration of the timeout. This means that the current node has not received a valid proposal during
this timeout, so it will prevote on `nil` (i.e. no block).
```
57: Function OnTimeoutPropose(height, round) :
58:   if height = h_p AND round = round_p AND step_p = propose then
59:     broadcast {PREVOTE, h_p, round_p, nil}
60:     step_p = prevote
```
---
Define the prevote timeout function.
If the prevote timeout elapses without advancing to the precommit stage, it means that the
current node did not see a majority prevote during the timeout. In this case the current
node will precommit to `nil` (i.e. no block).
```
61: Function OnTimeoutPrevote(height, round) :
62:   if height = hp AND round AND round_p AND step_p = prevote then
63:     broadcast {PRECOMMIT, h_p, round_p, nil}
64:     step_p = precommit
```
---
Define the precommit timeout function.
The purpose of this timeout is allowing the current node to collect as many precommits as possible
before moving on to the next round.
```
65: Function OnTimeoutPrecommit(height, round) :
66:   if height = h_p AND round = round_p then
67:     StartRound(round_p + 1)
```
