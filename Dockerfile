FROM gradle:7.4.2-jdk17
COPY --chown=gradle:gradle . /prior-auth/
RUN apt-get update         
RUN apt-get install -y git
WORKDIR /prior-auth/
RUN git clone https://github.com/HL7-DaVinci/CDS-Library.git
RUN gradle installBootDist

EXPOSE 3000/tcp
CMD ["gradle", "bootRun"]
