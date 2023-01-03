# xmake compiling

```
// compile workflow library
xmake

// compile test
xmake -g test
// run test
xmake run -g test

// compile tutorial
xmake -g tutorial

// compile benchmark
xmake -g benchmark
```

## running

`xmake run -h` can see which targets you can run

Select a target to run, for instance:

```
xmake run tutorial-06-parallel_wget
```

## xmake install

```
sudo xmake install
```

## Compile static / shared library

```
// compile static lib
xmake f -k static
xmake -r
```

```
// compile shard lib
xmake f -k shared
xmake -r
```

`tips : -r means -rebuild`

## build options

`xmake f --help` can see our defined options.

```
Command options (Project Configuration):

        --workflow_inc=WORKFLOW_INC        workflow inc (default: /media/psf/pro/workflow/_include)
        --upstream=[y|n]                   build upstream component (default: y)
        --consul=[y|n]                     build consul component
        --workflow_lib=WORKFLOW_LIB        workflow lib (default: /media/psf/pro/workflow/_lib)
        --redis=[y|n]                      build redis component (default: y)
        --kafka=[y|n]                      build kafka component
        --mysql=[y|n]                      build mysql component (default: y)
```

You can cut or integrate each components with the following commands

```
xmake f --redis=n --kafka=y --mysql=n
xmake -r
```
