Title: ATT&CK™ content available in STIX™ 2.0 via public TAXII™ 2.0 server
Date: 2018-05-14
Category: Cyber Threat Intelligence
Authors: Jen Burns, Anthony Masi
Summary: We are excited to announce that all of MITRE’s Adversarial Tactics, Techniques, and Common Knowledge content, including ATT&CK for Enterprise , PRE-ATT&CK™, and ATT&CK for Mobile, is now available via our [TAXII 2.0](https://oasis-open.github.io/cti-documentation/taxii/intro.html) server. This consolidation of content onto our TAXII server is another advancement toward our goal of making ATT&CK easier to use through [tooling and APIs](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/whats-next-for-attck%E2%84%A2). Prior to this announcement, we also released the ATT&CK content as [STIX 2.0](https://oasis-open.github.io/cti-documentation/stix/intro) in our [GitHub](https://github.com/mitre/cti) repository and published the [ATT&CK™ Navigator](https://github.com/mitre/attack-navigator), which uses the STIX 2.0 content to provide an interactive visualization of the ATT&CK matrices.

We are excited to announce that all of MITRE’s Adversarial Tactics, Techniques, and Common Knowledge content, including ATT&CK for Enterprise , PRE-ATT&CK™, and ATT&CK for Mobile, is now available via our [TAXII 2.0](https://oasis-open.github.io/cti-documentation/taxii/intro.html) server. This consolidation of content onto our TAXII server is another advancement toward our goal of making ATT&CK easier to use through [tooling and APIs](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/whats-next-for-attck%E2%84%A2). Prior to this announcement, we also released the ATT&CK content as [STIX 2.0](https://oasis-open.github.io/cti-documentation/stix/intro) in our [GitHub](https://github.com/mitre/cti) repository and published the [ATT&CK™ Navigator](https://github.com/mitre/attack-navigator), which uses the STIX 2.0 content to provide an interactive visualization of the ATT&CK matrices.

The TAXII server is an open-source module designed to serve STIX 2.0 content in compliance with the TAXII 2.0 [specification](https://oasis-open.github.io/cti-documentation/resources#taxii-20-specification). Written in JavaScript, it takes advantage of Node.js's asynchronous I/O model to handle incoming connections, allowing the server to handle connections smoothly under load. The module runs as a part of the overarching [Unfetter Discover](https://github.com/unfetter-discover) project, connected to a data store that contains the ATT&CK content expressed as STIX 2.0.

You can use existing and forthcoming libraries and tools to work with ATT&CK content, thanks to the move to STIX and TAXII. You can access ATT&CK content on our TAXII server through the [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) and [cti-taxii-client](https://github.com/oasis-open/cti-taxii-client) libraries. Under Department of Homeland Security sponsorship, MITRE developed both of these libraries and contributed to the OASIS Technical Committee for Cyber Threat Intelligence, which develops the STIX and TAXII standards.

Here is an example of how to use these libraries to print the names and IDs of each available ATT&CK technology-domain:
```
from stix2 import TAXIICollectionSource
from taxii2client import Server

# Instantiate server and get API Root
server = Server("https://cti-taxii.mitre.org/taxii/")
api_root = server.api_roots[0]

# Print name and ID of all ATT&CK technology-domains available as collections
for collection in api_root.collections:
          print(collection.title + ": " + collection.id)
```
The ID of each collection can then be used to get the content of that collection. Here's an example of using Enterprise ATT&CK’s ID to get that content. You'll see that changing the ID in the URL, which is highlighted in the code, allows you to get the content from another specified domain, such as ATT&CK for Mobile or PRE-ATT&CK.
```
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection

# Initialize dictionary to hold Enterprise ATT&CK content
attack = {}

# Establish TAXII2 Collection instance for Enterprise ATT&CK collection
collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")

# Supply the collection to TAXIICollection
tc_source = TAXIICollectionSource(collection)

# Create filters to retrieve content from Enterprise ATT&CK based on type
filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
          "mitigations": Filter("type", "=", "course-of-action"),
          "groups": Filter("type", "=", "intrusion-set"),
          "malware": Filter("type", "=", "malware"),
          "tools": Filter("type", "=", "tool"),
          "relationships": Filter("type", "=", "relationship")
}

# Retrieve all Enterprise ATT&CK content
for key in filter_objs:
          attack[key] = tc_source.query(filter_objs[key])

# For visual purposes, print the first technique received from the server
print(attack["techniques"][0])
```
With the introduction of this new TAXII 2 service for ATT&CK content, we are deprecating the existing MediaWiki APIs that are accessible via the [ATT&CK website](https://attack.mitre.org/). While the MediaWiki APIs will still be available for the short term, our intent is to transition completely to STIX/TAXII-based access. More information on the usage of the ATT&CK content expressed as STIX 2.0 can be found [here](https://github.com/mitre/cti/blob/master/USAGE.md).