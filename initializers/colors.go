package initializers

// I have adopted this for shell git coloring from: https://gist.github.com/vratiu/9780109
// #  Customize BASH PS1 prompt to show current GIT repository and branch.
// #  by Mike Stewart - http://MediaDoneRight.com

// #  SETUP CONSTANTS
// #  Bunch-o-predefined colors.  Makes reading code easier than escape sequences.
// Reset
const ColorOff = "\033[0m" // Text Reset

// Regular Colors
const (
	Black  = "\033[0;30m" // Black
	Red    = "\033[0;31m" // Red
	Green  = "\033[0;32m" // Green
	Yellow = "\033[0;33m" // Yellow
	Blue   = "\033[0;34m" // Blue
	Purple = "\033[0;35m" // Purple
	Cyan   = "\033[0;36m" // Cyan
	White  = "\033[0;37m" // White
)

// Bold
const (
	BBlack  = "\033[1;30m" // Black
	BRed    = "\033[1;31m" // Red
	BGreen  = "\033[1;32m" // Green
	BYellow = "\033[1;33m" // Yellow
	BBlue   = "\033[1;34m" // Blue
	BPurple = "\033[1;35m" // Purple
	BCyan   = "\033[1;36m" // Cyan
	BWhite  = "\033[1;37m" // White
)

// Underline
const (
	UBlack  = "\033[4;30m" // Black
	URed    = "\033[4;31m" // Red
	UGreen  = "\033[4;32m" // Green
	UYellow = "\033[4;33m" // Yellow
	UBlue   = "\033[4;34m" // Blue
	UPurple = "\033[4;35m" // Purple
	UCyan   = "\033[4;36m" // Cyan
	UWhite  = "\033[4;37m" // White
)

// Background
const (
	OnBlack  = "\033[40m" // Black
	OnRed    = "\033[41m" // Red
	OnGreen  = "\033[42m" // Green
	OnYellow = "\033[43m" // Yellow
	OnBlue   = "\033[44m" // Blue
	OnPurple = "\033[45m" // Purple
	OnCyan   = "\033[46m" // Cyan
	OnWhite  = "\033[47m" // White
)

// High Intensity
const (
	IBlack  = "\033[0;90m" // Black
	IRed    = "\033[0;91m" // Red
	IGreen  = "\033[0;92m" // Green
	IYellow = "\033[0;93m" // Yellow
	IBlue   = "\033[0;94m" // Blue
	IPurple = "\033[0;95m" // Purple
	ICyan   = "\033[0;96m" // Cyan
	IWhite  = "\033[0;97m" // White
)

// Bold High Intensity
const (
	BIBlack  = "\033[1;90m" // Black
	BIRed    = "\033[1;91m" // Red
	BIGreen  = "\033[1;92m" // Green
	BIYellow = "\033[1;93m" // Yellow
	BIBlue   = "\033[1;94m" // Blue
	BIPurple = "\033[1;95m" // Purple
	BICyan   = "\033[1;96m" // Cyan
	BIWhite  = "\033[1;97m" // White
)

// High Intensity backgrounds
const (
	OnIBlack  = "\033[0;100m" // Black
	OnIRed    = "\033[0;101m" // Red
	OnIGreen  = "\033[0;102m" // Green
	OnIYellow = "\033[0;103m" // Yellow
	OnIBlue   = "\033[0;104m" // Blue
	OnIPurple = "\033[10;95m" // Purple
	OnICyan   = "\033[0;106m" // Cyan
	OnIWhite  = "\033[0;107m" // White
)

/*
# Various variables you might want for your PS1 prompt instead
Time12h="\T"
Time12a="\@"
PathShort="\w"
PathFull="\W"
NewLine="\n"
Jobs="\j"


# This PS1 snippet was adopted from code for MAC/BSD I saw from: http://allancraig.net/index.php?option=com_content&view=article&id=108:ps1-export-command-for-git&catid=45:general&Itemid=96
# I tweaked it to work on UBUNTU 11.04 & 11.10 plus made it mo' better

export PS1=$IBlack$Time12h$Color_Off'$(git branch &>/dev/null;\
if [ $? -eq 0 ]; then \
  echo "$(echo `git status` | grep "nothing to commit" > /dev/null 2>&1; \
  if [ "$?" -eq "0" ]; then \
    # @4 - Clean repository - nothing to commit
    echo "'$Green'"$(__git_ps1 " (%s)"); \
  else \
    # @5 - Changes to working tree
    echo "'$IRed'"$(__git_ps1 " {%s}"); \
  fi) '$BYellow$PathShort$Color_Off'\$ "; \
else \
  # @2 - Prompt when not in GIT repo
  echo " '$Yellow$PathShort$Color_Off'\$ "; \
fi)'

# enable this flag ONLY if you are working with an internal repository that doesn't have a valid certificate
# export GIT_SSL_NO_VERIFY=true

git config --global alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%C(bold blue)<%an>%Creset' --abbrev-commit"

*/
