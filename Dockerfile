FROM python:3.8

RUN pip3.8 install numpy
RUN pip3.8 install sklearn
RUN pip3.8 install argparse
RUN pip3.8 install requests
RUN pip3.8 install uvicorn
RUN pip3.8 install fastapi
RUN pip3.8 install pydantic

RUN mkdir /http_attack_detection
COPY . /http_attack_detection
WORKDIR /http_attack_detection
