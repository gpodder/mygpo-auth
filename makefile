
test:
	envdir envs/dev/ python -Wd -m pytest --cov=mygpoauth/ --cov-branch
	coverage report --show-missing

install-deps:
	sudo apt-get install libffi-dev libpq-dev libjpeg-dev zlib1g-dev libwebp-dev

format-code:
	black --py36 --skip-string-normalization mygpoauth/

check-code-format:
	black --check --py36 --skip-string-normalization mygpoauth/

.PHONY: test install-deps
