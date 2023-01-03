# 编译

```
// 编译workflow库
xmake

// 编译test
xmake -g test
// 运行test文件
xmake run -g test

// 编译tutorial
xmake -g tutorial

// 编译benchmark
xmake -g benchmark
```

## 运行

`xmake run -h` 可以查看运行哪些target

选择一个target即可运行

比如

```
xmake run tutorial-06-parallel_wget
```

## 安装

```
sudo xmake install
```

## 切换编译静态库/动态库

```
// 编译静态库
xmake f -k static
xmake -r
```

```
// 编译动态库
xmake f -k shared
xmake -r
```

`tips : -r 代表 -rebuild`

## 进行定制化裁剪

`xmake f --help` 可查看我们定制的option

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

你可以通过如下命令来进行各个模块的裁剪或集成

```
xmake f --redis=n --kafka=y --mysql=n
xmake -r
```
