workflow "Build Extension" {
  on = "push"
  resolves = ["buildExtension"]
}

action "buildExtension" {
  uses = "beardypig/ghidra-buildExtension@master"
}
