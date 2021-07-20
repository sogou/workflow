# Contribution Guide

Sogou C++ Workflow is community-driven and welcomes any contributor. 

This document outlines some conventions about development steps, commit message formatting and contact points to make it easier to get your contribution accepted. 

-   [Code of Conduct](#code-of-conduct)
-   [Getting started](#getting-started)
-   [First Contribution](#first-contribution)
    -   [Find a good first topic](#find-a-good-first-topic)
    -   [Work on an existed issue](#work-on-an-existed-issue)
    -   [File a new issue](#file-a-new-issue)
-   [Contributor workflow](#contributor-workflow)
    -   [Creating Pull Requests](#creating-pull-requests)
    -   [Code Review](#code-review)
    -   [Testing and building](#testing-and-building)

# Code of Conduct

Please make sure to read and observe our [Code of Conduct](/CODE_OF_CONDUCT.md).

# Getting started

- Fork the repository on GitHub.
- Make your changes on your fork repository.
- Submit a PR.

# First Contribution

We will help you to contribute in different areas like filing issues, developing features, fixing critical bugs and getting your work reviewed and merged.

If you have questions about the development process, feel free to [file an issue](https://github.com/sogou/workflow/issues/new/choose).

We are always in need of help, be it fixing documentation, reporting bugs or writing some code.
Look at places where you feel best coding practices aren't followed, code refactoring is needed or tests are missing.
Here is how you get started.

### Find a good first topic

You can start by finding an existing issue with the 
[help-wanted](https://github.com/sogou/workflow/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) and
[good first issue](https://github.com/sogou/workflow/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
 label in this repository. These issues are well suited for new contributors as a beginner-friendly issues.

We can help new contributors who wish to work on such issues.

Another good way to contribute is to find a documentation improvement, such as a missing/broken link.

#### Work on an existed issue

When you are willing to take on an issue, just reply on the issue. The maintainer will assign it to you.

### File a new issue

While we encourage everyone to contribute code, it is also appreciated when someone reports an issue.

Please follow the prompted submission guidelines while opening an issue.

# Contributor workflow

To contribute to the code base, please follow the workflow as defined in this section.

1. Create a topic branch from where you want to base your work. This is usually master.
2. Make commits of logical units and add test case if the change fixes a bug or adds new functionality.
3. Run tests and make sure all the tests are passed.
4. Make sure your commit messages are in the proper format.
5. Push your changes to a topic branch in your fork of the repository.
6. Submit a pull request.

This is a rough outline of what a contributor's workflow looks like. For more details, you are encouraged to communicate with the reviewers before sending a pull request.

Thanks for your contributions!

## Creating Pull Requests

Our project generally follows the standard [github pull request](https://help.github.com/articles/about-pull-requests/) process.
To submit a proposed change, please develop the code/fix and add new test cases.
After that, run these local verifications before submitting pull request to predict the pass or fail of continuous integration.

## Code Review

To make it easier for your Pull Request to receive reviews, break large changes into a logical series of smaller patches which individually make easily understandable changes, and in aggregate solve a broader issue.

If this is an independent modification, then it is recommended that you provide a tutorial and corresponding documents, and communicate with us. 

## Testing and building

Make sure the  the [travis-ci](https://travis-ci.com/github/sogou/workflow/pull_requests) passed.

Once Your PR has been merged, you become a contributor. Thank you for your contribution!
