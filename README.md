# NetfilterFinalProject

# Projects

Projects will be performed in a group of two. Grades will be based on the following items.

Initial design (due two weeks from project announcement): 10% (April 6 2018)

A one page document pushed to GitHub describing how you plan on implementing your project and the resources you plan on using
Code, documentation, and final report (due April 23): 65%

Code: pushed to GitHub. This should include comments and error checking.
Documentation: a README in your repo with instructions on how to build, run and test your project.
Report: A document with an overview of your project, the implementation details, the main challenges, the division of work, and the result.
Presentation and demonstration (done at the time of the final exam, or earlier by appointment): 25%

A 6 slide presentation (title slide, overview, implementation, challenges, division of work, results)
Short demonstration of your project on your laptop
The three projects are:

Distributed Consensus
Netfilter
RamDisk
Alternatively, you can propose your own project.


# Design Requirements

## Network packet filtering module

In this project, you will build a Linux kernel module that monitors network traffic. Your module will allow users to specify things like “block all network traffic” and “print network traffic info” for a specified network address.

Your application will consist of a Linux kernel module that uses [netfilter](http://www.netfilter.org), a software packet filtering framework. Netfilter will let your kernel module register callback functions with the network stack. Netfilter is the library used by software like iptables to implement professional level firewalls.

[This link](http://www.tldp.org/LDP/lkmpg/2.6/html/lkmpg.html) will help you get started writing a module.

[This link](http://www.cs.uni.edu/~diesburg/courses/cop4610_fall10/week06/week6.pdf) is a little dated (for instance, the current kernel is at version 4.x and this link describes things for 2.6), but it will also help.

[This link](http://www.netfilter.org/) is the netfilter homepage, where you can find documentation about using netfilter with a kernel module. In particular, [this link](https://www.netfilter.org/documentation/HOWTO/networking-concepts-HOWTO-1.html) is an introduction to networking concepts.

## Requirements
Your project should allow users to do the following.

- Block or unblock all incoming traffic.
- Block or unblock all outgoing traffic.
- Block or unblock all traffic to a specific IP address.
- Display a list of the currently blocked IP addresses.
- Display the number of packets that have been blocked to/from the currently blocked addresses.

## Tips

Here are some tips that may help.
 
-To get the source and destination ip addresses, you'll need to look at the IP header. [This link](http://stackoverflow.com/questions/10025026/how-to-reach-struct-sk-buff-members) tells you how to do that:
 
-To compare against user inputted ip addresses to filter, you'll need to convert these addresses into another format. [This link](http://stackoverflow.com/questions/9296835/convert-source-ip-address-from-struct-iphdr-to-string-equivalent-using-linux-ne) shows how to do that
 
-[This link] (http://www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/) describes how to build a module that uses netfilter to drop all packets. The code it presents may compile, but some of the function signatures it uses may be wrong. In particular, this:

```c
unsigned int hook_func(unsigned int hooknum, 
    struct sk_buff **skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
```
 
Is no longer the signature of a hook function. It now looks like this:

```c
typedef unsigned int nf_hookfn(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state);
```
 
If you go to the kernel sources, you'll find that definition in the file include/linux/netfilter.h
 
You may find it frustrating that many of the code samples you find online don't compile with newer kernel versions. To understand why this is the case for out of tree modules (i.e., modules that aren't part of the official kernel sources), read the documentation in the file named "stable\_api\_nonsense.txt" in the Documentation/ directory of the Linux kernel sources.
 
-The proc file system entry you create will let you provide input to your module. There's a simple example in the examples repo on GitHub:
 
[examples](examples/)
 
Whenever the user writes to the /proc file that you register, you'll get a callback to the function you registered as the ".read" member in your file_operations variable. You can then do a simple parsing of their input to add the addresses that you need to filter and whether they are input or output.
 
-If you need to echo multiple lines at once to a file, you can use a "here" document, as described [here](http://stackoverflow.com/questions/10969953/how-to-output-a-multiline-string-in-bash).
 
For example:
 
$ cat << EOF >> /proc/filter
> 1
> 2
> EOF

(you need to press return after the first line, and then the ">" will appear).
 
Please post questions/issues/problems here on Piazza, and push your code to your repo so we can see it.