## Editing, building, and publishing extension documentation


The `datalad-extension-template` uses [Sphinx](https://www.sphinx-doc.org/en/master/index.html#) for document generation
and suggests using [Read the Docs](https://docs.readthedocs.io/en/stable/) for automatic documentation building, versioning, and hosting.

Once you are ready to document your extension software, take note of the following:

### Document editing

Edit your `docs/source/index.rst` file using [reStructuredText](https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html),
which is the default plaintext markup language used by Sphinx. Add further documentation as needed.

### Local testing

For testing locally whether your documentation builds and renders correctly, first install the developer requirements from the repository's root directory:
```
pip install -r requirements-devel.txt
```

Then build the documentation locally:
```
make -C docs html
```

Navigate to `docs/build/` and open `index.html` in your browser to view your documentation.
