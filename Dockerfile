FROM ubuntu:22.04

RUN apt-get update
RUN apt-get -y install python3 python3-pip python-is-python3 git gnuplot

RUN mkdir -p ~/didcomm-benchmarks
WORKDIR "~/didcomm-benchmarks"
RUN git clone https://github.com/jesusdiazvico/didcomm-privacy-benchmarks.git .
RUN pip install -r requirements.txt
RUN chmod +x get-stats.sh
RUN chmod +x get-all-stats-and-print.sh
RUN chmod +x get-all-stats-print-and-post.sh
RUN bash get-stats.sh anon 1000 results.anon; bash get-stats.sh auth 1000 results.auth; bash get-stats.sh naive-a-auth 1000 results.naive-a-auth; bash get-stats.sh merge-a-auth 1000 results.merge-a-auth; bash get-stats.sh ra-anon 1000 results.ra-anon; bash get-stats.sh ra-a-auth 1000 results.ra-a-auth
RUN gnuplot print-stats-enc-cpu.gp; gnuplot print-stats-dec-cpu.gp; gnuplot print-stats-size.gp
RUN mkdir -p flask-app/static
RUN cp results-enc.png flask-app/static; cp results-dec.png flask-app/static; cp results-size.png flask-app/static
ENV FLASK_APP flask-app/application.py
CMD ["flask", "run", "--host", "0.0.0.0"]
