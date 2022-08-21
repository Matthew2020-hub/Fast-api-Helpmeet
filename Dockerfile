
# pull the official docker image
FROM python:3.9.7

# set env variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Only update packages
RUN apt-get update

# set work directory
WORKDIR ./project

# cpy requirements files
COPY requirements.txt /project/requirements.txt

# install requirements
RUN pip install -r requirements.txt

# copy codebbase
COPY . /project/

# create a new user
RUN adduser --disabled-password --gecos '' respect

# Set user as the owner of directory
RUN chown -R respect:respect /project

# Set user to be timescribe
USER respect