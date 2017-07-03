
test:
	envdir envs/dev/ coverage run --branch --source=mygpoauth ./manage.py test
	coverage report --show-missing

install-deps:
	sudo apt-get install libffi-dev libpq-dev libjpeg-dev zlib1g-dev libwebp-dev

.PHONY: test install-deps
