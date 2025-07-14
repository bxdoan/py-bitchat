"""
Terminal UX module for BitChat Terminal

Handles chat context, formatting, and user interface elements
Compatible with the Rust implementation.
"""

import sys
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass


class ChatMode(Enum):
    """Chat mode enumeration"""
    PUBLIC = "public"
    CHANNEL = "channel"
    PRIVATE_DM = "private_dm"


@dataclass
class ChatContext:
    """
    Manages the current chat context and conversation state
    """
    
    def __init__(self):
        self.current_mode = ChatMode.PUBLIC
        self.current_channel: Optional[str] = None
        self.current_dm_nickname: Optional[str] = None
        self.current_dm_peer_id: Optional[str] = None
        
        # Track active conversations
        self.active_channels: List[str] = []
        self.active_dms: List[Tuple[str, str]] = []  # (nickname, peer_id)
        
        # Last private message sender for /reply command
        self.last_private_sender: Optional[Tuple[str, str]] = None  # (peer_id, nickname)
    
    def switch_to_public(self):
        """Switch to public chat mode"""
        self.current_mode = ChatMode.PUBLIC
        self.current_channel = None
        self.current_dm_nickname = None
        self.current_dm_peer_id = None
        print("» Switched to public chat")
    
    def switch_to_channel(self, channel: str):
        """Switch to a specific channel"""
        self.current_mode = ChatMode.CHANNEL
        self.current_channel = channel
        self.current_dm_nickname = None
        self.current_dm_peer_id = None
        
        # Add to active channels if not already there
        if channel not in self.active_channels:
            self.active_channels.append(channel)
        
        print(f"» Switched to channel {channel}")
    
    def switch_to_channel_silent(self, channel: str):
        """Switch to channel without printing message"""
        self.current_mode = ChatMode.CHANNEL
        self.current_channel = channel
        self.current_dm_nickname = None
        self.current_dm_peer_id = None
        
        if channel not in self.active_channels:
            self.active_channels.append(channel)
    
    def enter_dm_mode(self, nickname: str, peer_id: str):
        """Enter DM mode with a specific user"""
        self.current_mode = ChatMode.PRIVATE_DM
        self.current_channel = None
        self.current_dm_nickname = nickname
        self.current_dm_peer_id = peer_id
        
        # Add to active DMs if not already there
        dm_tuple = (nickname, peer_id)
        if dm_tuple not in self.active_dms:
            self.active_dms.append(dm_tuple)
        
        print(f"» Started DM with {nickname}")
    
    def add_channel(self, channel: str):
        """Add a channel to active list without switching"""
        if channel not in self.active_channels:
            self.active_channels.append(channel)
    
    def add_dm(self, nickname: str, peer_id: str):
        """Add a DM to active list without switching"""
        dm_tuple = (nickname, peer_id)
        if dm_tuple not in self.active_dms:
            self.active_dms.append(dm_tuple)
    
    def remove_channel(self, channel: str):
        """Remove a channel from active list"""
        if channel in self.active_channels:
            self.active_channels.remove(channel)
    
    def format_prompt(self) -> str:
        """Get the formatted prompt for current context"""
        if self.current_mode == ChatMode.PUBLIC:
            return "public"
        elif self.current_mode == ChatMode.CHANNEL:
            return f"{self.current_channel}"
        elif self.current_mode == ChatMode.PRIVATE_DM:
            return f"dm:{self.current_dm_nickname}"
        return "unknown"
    
    def get_status_line(self) -> str:
        """Get status line showing current context"""
        if self.current_mode == ChatMode.PUBLIC:
            return "» Public chat"
        elif self.current_mode == ChatMode.CHANNEL:
            return f"» Channel: {self.current_channel}"
        elif self.current_mode == ChatMode.PRIVATE_DM:
            return f"» DM with {self.current_dm_nickname}"
        return "» Unknown mode"
    
    def get_conversation_list_with_numbers(self) -> str:
        """Get formatted conversation list with numbers for switching"""
        lines = ["Available conversations:"]
        count = 1
        
        # Add public chat
        lines.append(f"  {count}. Public chat")
        count += 1
        
        # Add channels
        for channel in self.active_channels:
            lines.append(f"  {count}. {channel}")
            count += 1
        
        # Add DMs
        for nickname, _ in self.active_dms:
            lines.append(f"  {count}. DM with {nickname}")
            count += 1
        
        return "\n".join(lines)
    
    def switch_to_number(self, num: int) -> bool:
        """Switch to conversation by number"""
        count = 1
        
        # Public chat is always #1
        if num == count:
            self.switch_to_public()
            return True
        count += 1
        
        # Check channels
        for channel in self.active_channels:
            if num == count:
                self.switch_to_channel(channel)
                return True
            count += 1
        
        # Check DMs
        for nickname, peer_id in self.active_dms:
            if num == count:
                self.enter_dm_mode(nickname, peer_id)
                return True
            count += 1
        
        return False
    
    def show_conversation_list(self):
        """Show the conversation list"""
        if not self.active_channels and not self.active_dms:
            print("» No active conversations. Type a message to start chatting!")
            return
        
        print("\nActive conversations:")
        
        if self.active_channels:
            print("  Channels:")
            for channel in self.active_channels:
                current = " (current)" if (self.current_mode == ChatMode.CHANNEL and 
                                         self.current_channel == channel) else ""
                print(f"    {channel}{current}")
        
        if self.active_dms:
            print("  DMs:")
            for nickname, _ in self.active_dms:
                current = " (current)" if (self.current_mode == ChatMode.PRIVATE_DM and 
                                         self.current_dm_nickname == nickname) else ""
                print(f"    {nickname}{current}")
        
        public_current = " (current)" if self.current_mode == ChatMode.PUBLIC else ""
        print(f"  Public chat{public_current}")


def format_message_display(
    timestamp: datetime,
    sender: str,
    content: str,
    is_private: bool,
    is_channel: bool,
    channel_name: Optional[str],
    recipient: Optional[str],
    my_nickname: str
) -> str:
    """
    Format a message for display in the terminal
    
    Args:
        timestamp: Message timestamp
        sender: Sender nickname
        content: Message content
        is_private: True if private message
        is_channel: True if channel message
        channel_name: Channel name if applicable
        recipient: Recipient nickname for private messages
        my_nickname: Current user's nickname
        
    Returns:
        Formatted message string
    """
    time_str = timestamp.strftime("%H:%M")
    
    if is_private:
        if sender == my_nickname:
            # Outgoing private message
            return f"\033[90m{time_str}\033[0m \033[35m→ {recipient}\033[0m {content}"
        else:
            # Incoming private message
            return f"\033[90m{time_str}\033[0m \033[35m← {sender}\033[0m {content}"
    elif is_channel and channel_name:
        # Channel message
        if sender == my_nickname:
            return f"\033[90m{time_str}\033[0m \033[36m{channel_name}\033[0m \033[32m{sender}\033[0m {content}"
        else:
            return f"\033[90m{time_str}\033[0m \033[36m{channel_name}\033[0m \033[33m{sender}\033[0m {content}"
    else:
        # Public message
        if sender == my_nickname:
            return f"\033[90m{time_str}\033[0m \033[32m{sender}\033[0m {content}"
        else:
            return f"\033[90m{time_str}\033[0m \033[33m{sender}\033[0m {content}"


def print_help():
    """Print help information"""
    help_text = """
\033[38;5;46mBitChat Terminal Commands\033[0m
\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m

\033[33mBasic Commands:\033[0m
  /help                  Show this help message
  /exit                  Exit BitChat
  /clear                 Clear the terminal screen
  /status                Show connection status
  
\033[33mChat & Messaging:\033[0m
  /dm <nickname>         Start DM with user or send quick message
  /dm <nickname> <msg>   Send a private message directly
  /reply                 Reply to last private message received
  /public                Switch back to public chat
  
\033[33mChannels:\033[0m
  /j #channel            Join a public channel
  /j #channel <password> Join a password-protected channel
  /channels              List discovered channels
  /leave                 Leave current channel
  /pass <password>       Set password for current channel (owner only)
  /transfer @user        Transfer channel ownership (owner only)
  
\033[33mConversation Management:\033[0m
  /list                  Show active conversations
  /switch                Interactive conversation switcher
  1, 2, 3...             Quick switch to conversation by number
  
\033[33mUser Management:\033[0m
  /name <nickname>       Change your nickname
  /online                Show online users
  /block @user           Block a user
  /unblock @user         Unblock a user
  
\033[33mMessage Colors:\033[0m
  \033[33mYellow\033[0m = Other users' public messages
  \033[32mGreen\033[0m  = Your messages  
  \033[35mPurple\033[0m = Private messages (→ outgoing, ← incoming)
  \033[36mCyan\033[0m   = Channel names
  \033[90mGray\033[0m   = Timestamps and system messages

\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
Just type a message and press Enter to send to current chat context.
"""
    print(help_text)


def clear_terminal():
    """Clear the terminal screen"""
    if sys.platform.startswith('win'):
        import os
        os.system('cls')
    else:
        print('\033[2J\033[1;1H', end='')


def print_logo():
    """Print the BitChat ASCII logo"""
    logo = """
\033[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\
## |      \\__|  ## |              ## |                 ## |
#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\
##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|
## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |
## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\
#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |
\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\033[0m

\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
\033[37mDecentralized • Encrypted • Peer-to-Peer • Open Source\033[0m
\033[37m                bitchat the terminal v1.0.0\033[0m
\033[37m                Email: bxdoan93@gmail.com\033[0m
\033[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
"""
    print(logo)


def format_connection_status(peer_count: int, channel_count: int, dm_count: int, nickname: str, peer_id: str) -> str:
    """Format connection status display"""
    # Truncate nickname if too long
    display_nickname = nickname[:9] if len(nickname) > 9 else nickname
    
    status = f"""
╭─── Connection Status ───╮
│ Peers connected: {peer_count:3}    │
│ Active channels: {channel_count:3}    │
│ Active DMs:      {dm_count:3}    │
│                         │
│ Your nickname: {display_nickname:^9}│
│ Your ID: {peer_id[:8]}...│
╰─────────────────────────╯"""
    
    return status 