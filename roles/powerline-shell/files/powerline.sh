function _update_ps1() {
    export PS1="$(${HOME}/bin/powerline_shell bash)"
}

export PROMPT_COMMAND="_update_ps1; $PROMPT_COMMAND"
