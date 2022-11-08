# PyCOMPSs Yorc plugin

This project allows to interact with PyCOMPSs using a Yorc plugin.

## Build & Install

### Yorc part

Build from sources:

```bash
git clone https://github.com/eflows4hpc/pycompss-yorc-plugin
cd pycompss-yorc-plugin
CGO_ENABLED=0 go build .
```

The builded binary should be stored **as an executable file** under the
[`plugins` directory of your Yorc instance](https://yorc.readthedocs.io/en/stable/configuration.html#option-pluginsdir-cmd).

### Alien4Cloud TOSCA definitions

[`tosca/alien/types.yaml`](tosca/alien/types.yaml) contains the TOSCA definitions to be imported in Alien4Cloud.

## License

This project is licensed under the [Apache 2.0 license](LICENSE).
