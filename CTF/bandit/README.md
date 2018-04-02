CTF game at http://overthewire.org/wargames/bandit/

Storing here some of the passwords to continue on playing:
(password to access level, those omitted, are obtained in a different manner)
- level 9: UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
- level 10: truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
- level 11: IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
- level 12: 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
- level 13: 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
- level 15: BfMYroe26WYalil77FoDi9qh59eK5xNr
- level 16: cluFn7wTiGryunymYOu4RcffSxQluehd
- level 19: IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
- level 20: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
- level 21: gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
- level 22: Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
- level 23: jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
- level 24: UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
- level 25: uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
- level 25: uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
- level 26: 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z

### Detailed walkthrough:

#### Level 24
Used the following script:
```bash
#!/bin/bash
mkdir -p /tmp/dir098
cat /etc/bandit_pass/bandit24 > /tmp/dir098/password.txt
mkdir -p /tmp/created3
```

#### level 25
https://gist.github.com/ghzmdr/7bdf4249e67a2ff7ed3f (in particular, the last option is the fastest)


#### level 26
First approach at:
https://kongwenbin.wordpress.com/2016/09/11/overthewire-bandit-level-25-to-level-26/

When entering `vim` from `more`, editing the file `/tmp/bandit27.swp` (`:e /tmp/bandit27.swp`) gets us at the end
`yRbXh6lQbmIOWvPT6Z`.

Solved at http://codebluedev.blogspot.com.es/2015/07/overthewire-bandit-level-26.html.

### Bibliography
- https://infamoussyn.com/2013/11/08/overthewire-bandit-level-0-25-writeup-completed
