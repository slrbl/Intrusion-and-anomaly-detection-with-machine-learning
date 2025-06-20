FROM python:3.8

RUN pip3.8 install configparser
RUN pip3.8 install requests
RUN pip3.8 install pydantic
RUN pip3.8 install argparse
RUN pip3.8 install sklearn
RUN pip3.8 install uvicorn
RUN pip3.8 install fastapi
RUN pip3.8 install numpy

RUN mkdir /webhawk
COPY . /webhawk
WORKDIR /webhawk
