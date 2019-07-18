web: python setup.py sdist && \
  pip install dist/sponsor-cat-*.tar.gz && \
  flask init-db && \
  waitress-serve --port=$PORT --call 'sponsor-cat:create_app'
