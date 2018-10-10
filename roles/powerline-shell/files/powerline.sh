export PROMPT_COMMAND='history -a; history -n; shopt -s histappend; printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"'

function _update_ps1() {
    export PS1="$(${HOME}/bin/powerline_shell bash)"
}

export PROMPT_COMMAND="_update_ps1; $PROMPT_COMMAND"
