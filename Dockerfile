# debug CI: docker build -t rhmci .

FROM ubuntu:20.04

RUN apt-get update || true \
    && apt install -y curl wget python3 python3-pip git

# install pandoc 2.16.2
RUN wget https://github.com/jgm/pandoc/releases/download/2.16.2/pandoc-2.16.2-1-amd64.deb && \
      dpkg -i pandoc-2.16.2-1-amd64.deb

# ## install pandoc-sidenote from source
# # install stack
# RUN curl -sSL https://get.haskellstack.org/ | sh
#
# # install pandoc-sidenote from source
# RUN git clone https://github.com/jez/pandoc-sidenote && \
#     cd pandoc-sidenote && stack build && stack install

RUN apt-get install -y  cabal-install && \
    cabal update && cabal install pandoc-sidenote && \
    ln -s /root/.cabal/bin/pandoc-sidenote /usr/bin/pandoc-sidenote
RUN pip3 install pandoc-latex-fontsize
COPY . /robot_hacking_manual

WORKDIR /robot_hacking_manual
RUN make clean; make html
