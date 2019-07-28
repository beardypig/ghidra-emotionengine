workflow "Build on push" {
  resolves = ["Build Extension"]
  on = "push"
}

action "Build Extension" {
  uses = "beardypig/action-ghidra-buildextension@master"
}
