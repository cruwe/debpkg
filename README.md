# debpkg
prototypes for extending dpkg script functionailities

## audit
returns a list of packages with open vulnerabilities, corresponding CVE-# and 
description. 
May return more than one hit per package as packages may be vulnerable for 
multiple reasons.
Does not (yet) list packages with fixed vulnerabilites.
 
## leaves
returns a list of packages which no other installed package depends on. 
This consitutes a "leaf" as opposed to a "node" in the package tree.
