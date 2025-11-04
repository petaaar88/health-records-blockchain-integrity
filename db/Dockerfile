FROM mongo:latest

COPY dump /dump

CMD mongod --bind_ip_all & sleep 5 && mongorestore /dump && tail -f /dev/null
