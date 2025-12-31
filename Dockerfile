FROM python:alpine

WORKDIR /server

COPY . /server

EXPOSE 1080

ENTRYPOINT ["python", "main.py"]