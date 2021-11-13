# History
This project started back in early 2018 by [Víctor Mayoral-Vilches](https://www.linkedin.com/in/vmayoral) as a series of independent markdown and Docker-based write-ups and has now converged into a manual that hopes help others enter the field of robot cybersecurity.

# Motivation

Robots are often shipped insecure and in some cases fully unprotected. The rationale behind is fourfold: first, defensive security mechanisms for robots are still on their early stages, not covering the complete threat landscape. Second, the inherent complexity of robotic systems makes their protection costly, both technically and economically. Third, robot vendors do not generally take responsibility in a timely manner, extending the zero-days exposure window (time until mitigation of a zero-day) to several years on average. Fourth, contrary to the common-sense expectations in 21st century and similar
to Ford in the 1920s with cars, most robot manufacturers oppose or difficult robot repairs. They employ planned obsolescence practices to discourage repairs and evade competition.

Cybersecurity in robotics is crucial. Specially given the safety hazards that appear with robots (**#nosafetywithoutsecurity** in robotics). After observing for a few years how several manufacturers keep forwarding these problems to the end-users of these machines (their clients), this manual aims to empower robotics teams and security practitioners with the right knowhow to secure robots from an offensive perspective.


# A containerized approach

Robotics is the art of system integration. It's a very engineering-oriented field where systematic reproduction of results is key for mitigation of security flaws. Docker containers are widely used throughout the manual while presenting PoCs to ensure that practitioners have a common, consistent and easily reproducible development environment. This facilitates the security process and the collaboration across teams.
