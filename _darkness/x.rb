# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end
         

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
# make useless file ruby for gh identity it's ruby
#######################################################

case
when song.name == 'Misty'
  puts 'Not again!'
when song.duration > 120
  puts 'Too long!'
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end

kind = case year
       when 1850..1889 then 'Blues'
       when 1890..1909 then 'Ragtime'
       when 1910..1929 then 'New Orleans Jazz'
       when 1930..1939 then 'Swing'
       when 1940..1950 then 'Bebop'
       else 'Jazz'
       end

# bad
def self.create_translation(phrase_id, phrase_key, target_locale,
                            value, user_id, do_xss_check, allow_verification)
  ...
end

# good
def self.create_translation(phrase_id,
                            phrase_key,
                            target_locale,
                            value,
                            user_id,
                            do_xss_check,
                            allow_verification)
  ...
end

# good
def self.create_translation(
  phrase_id,
  phrase_key,
  target_locale,
  value,
  user_id,
  do_xss_check,
  allow_verification
)
  ...
end
# bad
result = func(a, b)# we might want to change b to c

# good
result = func(a, b) # we might want to change b to c

sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts 'Hi'
[1, 2, 3].each { |e| puts e }

if @reservation_alteration.checkin == @reservation.start_date &&
   @reservation_alteration.checkout == (@reservation.start_date + @reservation.nights)

  redirect_to_alteration @reservation_alteration
end

# bad
class Foo

  def bar
    # body omitted
  end

end

# good
class Foo
  def bar
    # body omitted
  end
end

def transformorize_car
  car = manufacture(options)
  t = transformer(robot, disguise)

  car.after_market_mod!
  t.transform(car)
  car.assign_cool_name!

  fleet.add(car)
  car
end

# Automatic conversion of one locale to another where it is possible, like
# American to British English.
module Translation
  # Class for converting between text between similar locales.
  # Right now only conversion between American English -> British, Canadian,
  # Australian, New Zealand variations is provided.
  class PrimAndProper
    def initialize
      @converters = { :en => { :"en-AU" => AmericanToAustralian.new,
                               :"en-CA" => AmericanToCanadian.new,
                               :"en-GB" => AmericanToBritish.new,
                               :"en-NZ" => AmericanToKiwi.new,
                             } }
    end

  ...

  # Applies transforms to American English that are common to
  # variants of all other English colonies.
  class AmericanToColonial
    ...
  end

  # Converts American to British English.
  # In addition to general Colonial English variations, changes "apartment"
  # to "flat".
  class AmericanToBritish < AmericanToColonial
    ...
  end
All files, including data and config files, should have file-level comments.

# List of American-to-British spelling variants.
#
# This list is made with
# lib/tasks/list_american_to_british_spelling_variants.rake.
#
# It contains words with general spelling variation patterns:
#   [trave]led/lled, [real]ize/ise, [flav]or/our, [cent]er/re, plus
# and these extras:
#   learned/learnt, practices/practises, airplane/aeroplane, ...


# bad
def obliterate(things, gently = true, except = [], at = Time.now)
  ...
end

# good
def obliterate(things, gently: true, except: [], at: Time.now)
  ...
end

# good
def obliterate(things, options = {})
  options = {
    :gently => true, # obliterate with soft-delete
    :except => [], # skip obliterating these things
    :at => Time.now, # don't obliterate them until later
  }.merge(options)

  ...
end

worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 15
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end
end
         
 # encoding: utf-8

begin
  require 'bundler/setup'
rescue LoadError => e
  warn e.message
  warn "Run `gem install bundler` to install Bundler"
  exit -1
end

LANGUAGES = %w[bg de en es fr id it ja ko pl pt ru tr vi zh_cn zh_tw]
CONFIG = "_config.yml"

task :default => [:build]
task :ci      => [:test, :build]

desc "Build the Jekyll site"
task :build do
  require "lanyon"

  Lanyon.build
end

namespace :build do

  def build_subpage(lang)
    require "yaml"
    require "lanyon"

    exclude_config = YAML.load_file(CONFIG)["exclude"]
    exclude_langs  = (LANGUAGES - [lang]).map {|x| "#{x}/" }

    exclude = exclude_config + exclude_langs

    Lanyon.build(exclude: exclude)
  end

  desc "Build the Jekyll site (`lang' language part only)"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      build_subpage(lang)
    end
  end
end

desc "Serve the Jekyll site locally"
task :serve do
  sh "rackup config.ru"
end

namespace :new_post do

  def create_template(lang)
    url_title = 'short-title'
    title = 'Post Title'

    now = Time.now.utc
    datetime = now.strftime("%Y-%m-%d %H:%M:%S %z")
    date = now.strftime("%Y-%m-%d")
    filename = "#{date}-#{url_title}.md"
    path = File.join(lang, 'news', '_posts', filename)

    content = <<-TEMPLATE.gsub(/^ */, '')
      ---
      layout: news_post
      title: "#{title}"
      author: "Unknown Author"
      translator:
      date: #{datetime}
      lang: #{lang}
      ---
      Content.
    TEMPLATE

    $stderr.print "Creating template `#{path}'... "
    begin
      if File.exist?(path)
        warn "Could not create template, `#{path}' already exists."
      else
        File.open(path, 'w') {|f| f.write content }
        warn 'done.'
      end
    rescue => e
      warn e.message
    end
  end

  desc "Create a news post template for language `lang'"
  task :lang do
    puts 'Please specify one of the valid language codes:'
    puts LANGUAGES.join(', ') << '.'
  end

  LANGUAGES.each do |lang|
    task lang.to_sym do
      create_template(lang)
    end
  end
end

desc "Alias for `check'"
task :test => [:check]

desc "Run some tests on markdown files"
task :check do
  require_relative "lib/linter"
  Linter.new.run
end

namespace :check do

  localport = 9292

  desc "Check for broken internal links on http://localhost:#{localport}/"
  task :links do
    require_relative "lib/link_checker"
    LinkChecker.new.check(localport: localport, languages: LANGUAGES)
  end

  desc 'Validate _site markup with validate-website'
  task :markup do
    require_relative "lib/markup_checker"
    MarkupChecker.new.check
  end
end

Ransack::Adapters.object_mapper.require_constants

module Ransack
  extend Configuration
  class UntraversableAssociationError < StandardError; end;
end

Ransack.configure do |config|
  Ransack::Constants::AREL_PREDICATES.each do |name|
    config.add_predicate name, :arel_predicate => name
  end
  Ransack::Constants::DERIVED_PREDICATES.each do |args|
    config.add_predicate(*args)
  end
end

require 'ransack/search'
require 'ransack/ransacker'
require 'ransack/helpers'
require 'action_controller'
require 'ransack/translate'

Ransack::Adapters.object_mapper.require_adapter

ActiveSupport.on_load(:action_controller) do
  ActionController::Base.helper Ransack::Helpers::FormHelper
end

module Ransack
  module Adapters

    def self.object_mapper
      @object_mapper ||= instantiate_object_mapper
    end

    def self.instantiate_object_mapper
      if defined?(::ActiveRecord::Base)
        ActiveRecordAdapter.new
      elsif defined?(::Mongoid)
        MongoidAdapter.new
      else
        raise "Unsupported adapter"
      end
    end

    class ActiveRecordAdapter
      def require_constants
        require 'ransack/adapters/active_record/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/active_record/ransack/translate'
        require 'ransack/adapters/active_record'
      end

      def require_context
        require 'ransack/adapters/active_record/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/active_record/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/active_record/ransack/context'
      end
    end

    class MongoidAdapter
      def require_constants
        require 'ransack/adapters/mongoid/ransack/constants'
      end

      def require_adapter
        require 'ransack/adapters/mongoid/ransack/translate'
        require 'ransack/adapters/mongoid'
      end

      def require_context
        require 'ransack/adapters/mongoid/ransack/visitor'
      end

      def require_nodes
        require 'ransack/adapters/mongoid/ransack/nodes/condition'
      end

      def require_search
        require 'ransack/adapters/mongoid/ransack/context'
      end
    end
  end
end


module Ransack
  module Configuration

    mattr_accessor :predicates, :options

    class PredicateCollection
      attr_reader :sorted_names_with_underscores

      def initialize
        @collection = {}
        @sorted_names_with_underscores = []
      end

      delegate :[], :keys, :has_key?, to: :@collection

      def []=(key, value)
        @sorted_names_with_underscores << [key, '_' + key]
        @sorted_names_with_underscores.sort! { |(a, _), (b, _)| b.length <=> a.length }

        @collection[key] = value
      end
    end

    self.predicates = PredicateCollection.new

    self.options = {
      :search_key => :q,
      :ignore_unknown_conditions => true,
      :hide_sort_order_indicators => false,
      :up_arrow => '&#9660;'.freeze,
      :down_arrow => '&#9650;'.freeze,
      :default_arrow => nil,
      :sanitize_scope_args => true
    }

    def configure
      yield self
    end

    def add_predicate(name, opts = {})
      name = name.to_s
      opts[:name] = name
      compounds = opts.delete(:compounds)
      compounds = true if compounds.nil?
      compounds = false if opts[:wants_array]

      self.predicates[name] = Predicate.new(opts)

      Constants::SUFFIXES.each do |suffix|
        compound_name = name + suffix
        self.predicates[compound_name] = Predicate.new(
          opts.merge(
            :name => compound_name,
            :arel_predicate => arel_predicate_with_suffix(
              opts[:arel_predicate], suffix
              ),
            :compound => true
          )
        )
      end if compounds
    end

    # The default `search_key` name is `:q`. The default key may be overridden
    # in an initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Name the search_key `:query` instead of the default `:q`
    #   config.search_key = :query
    # end
    #
    # Sometimes there are situations when the default search parameter name
    # cannot be used, for instance if there were two searches on one page.
    # Another name can be set using the `search_key` option with Ransack
    # `ransack`, `search` and `@search_form_for` methods in controllers & views.
    #
    # In the controller:
    # @search = Log.ransack(params[:log_search], search_key: :log_search)
    #
    # In the view:
    # <%= f.search_form_for @search, as: :log_search %>
    #
    def search_key=(name)
      self.options[:search_key] = name
    end

    # By default Ransack ignores errors if an unknown predicate, condition or
    # attribute is passed into a search. The default may be overridden in an
    # initializer file like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Raise if an unknown predicate, condition or attribute is passed
    #   config.ignore_unknown_conditions = false
    # end
    #
    def ignore_unknown_conditions=(boolean)
      self.options[:ignore_unknown_conditions] = boolean
    end

    # By default, Ransack displays sort order indicator arrows with HTML codes:
    #
    #   up_arrow:   '&#9660;'
    #   down_arrow: '&#9650;'
    #
    # There is also a default arrow which is displayed if a column is not sorted.
    # By default this is nil so nothing will be displayed.
    #
    # Any of the defaults may be globally overridden in an initializer file
    # like `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Globally set the up arrow to an icon, and the down and default arrows to unicode.
    #   config.custom_arrows = {
    #     up_arrow:   '<i class="fa fa-long-arrow-up"></i>',
    #     down_arrow: 'U+02193',
    #     default_arrow: 'U+11047'
    #   }
    # end
    #
    def custom_arrows=(opts = {})
      self.options[:up_arrow] = opts[:up_arrow].freeze if opts[:up_arrow]
      self.options[:down_arrow] = opts[:down_arrow].freeze if opts[:down_arrow]
      self.options[:default_arrow] = opts[:default_arrow].freeze if opts[:default_arrow]
    end

    # Ransack sanitizes many values in your custom scopes into booleans.
    # [1, '1', 't', 'T', 'true', 'TRUE'] all evaluate to true.
    # [0, '0', 'f', 'F', 'false', 'FALSE'] all evaluate to false.
    #
    # This default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Accept my custom scope values as what they are.
    #   config.sanitize_custom_scope_booleans = false
    # end
    #
    def sanitize_custom_scope_booleans=(boolean)
      self.options[:sanitize_scope_args] = boolean
    end

    # By default, Ransack displays sort order indicator arrows in sort links.
    # The default may be globally overridden in an initializer file like
    # `config/initializers/ransack.rb` as follows:
    #
    # Ransack.configure do |config|
    #   # Hide sort link order indicators globally across the application
    #   config.hide_sort_order_indicators = true
    # end
    #
    def hide_sort_order_indicators=(boolean)
      self.options[:hide_sort_order_indicators] = boolean
    end

    def arel_predicate_with_suffix(arel_predicate, suffix)
      if arel_predicate === Proc
        proc { |v| "#{arel_predicate.call(v)}#{suffix}" }
      else
        "#{arel_predicate}#{suffix}"
      end
    end

  end
end
  
  module Ransack
  module Constants
    OR                  = 'or'.freeze
    AND                 = 'and'.freeze

    CAP_SEARCH          = 'Search'.freeze
    SEARCH              = 'search'.freeze
    SEARCHES            = 'searches'.freeze

    ATTRIBUTE           = 'attribute'.freeze
    ATTRIBUTES          = 'attributes'.freeze
    COMBINATOR          = 'combinator'.freeze

    TWO_COLONS          = '::'.freeze
    UNDERSCORE          = '_'.freeze
    LEFT_PARENTHESIS    = '('.freeze
    Q                   = 'q'.freeze
    I                   = 'i'.freeze
    DOT_ASTERIX         = '.*'.freeze

    STRING_JOIN         = 'string_join'.freeze
    ASSOCIATION_JOIN    = 'association_join'.freeze
    STASHED_JOIN        = 'stashed_join'.freeze
    JOIN_NODE           = 'join_node'.freeze

    TRUE_VALUES = [true, 1, '1', 't', 'T', 'true', 'TRUE'].to_set
    FALSE_VALUES = [false, 0, '0', 'f', 'F', 'false', 'FALSE'].to_set
    BOOLEAN_VALUES = (TRUE_VALUES + FALSE_VALUES).freeze

    AND_OR              = ['and'.freeze, 'or'.freeze].freeze
    IN_NOT_IN           = ['in'.freeze, 'not_in'.freeze].freeze
    SUFFIXES            = ['_any'.freeze, '_all'.freeze].freeze
    AREL_PREDICATES     = [
      'eq'.freeze, 'not_eq'.freeze,
      'matches'.freeze, 'does_not_match'.freeze,
      'lt'.freeze, 'lteq'.freeze,
      'gt'.freeze, 'gteq'.freeze,
      'in'.freeze, 'not_in'.freeze
      ].freeze
    A_S_I               = ['a'.freeze, 's'.freeze, 'i'.freeze].freeze

    EQ                  = 'eq'.freeze
    NOT_EQ              = 'not_eq'.freeze
    EQ_ANY              = 'eq_any'.freeze
    NOT_EQ_ALL          = 'not_eq_all'.freeze
    CONT                = 'cont'.freeze

    RAILS_5_1           = '5.1'.freeze
    RAILS_5_2           = '5.2'.freeze
    RAILS_5_2_0         = '5.2.0'.freeze
    RAILS_6_0           = '6.0.0'.freeze

    RANSACK_SLASH_SEARCHES = 'ransack/searches'.freeze
    RANSACK_SLASH_SEARCHES_SLASH_SEARCH = 'ransack/searches/search'.freeze
  end
end
  
  module Ransack
  class Ransacker

    attr_reader :name, :type, :formatter, :args

    delegate :call, :to => :@callable

    def initialize(klass, name, opts = {}, &block)
      @klass, @name = klass, name

      @type = opts[:type] || :string
      @args = opts[:args] || [:parent]
      @formatter = opts[:formatter]
      @callable = opts[:callable] || block ||
                  (@klass.method(name) if @klass.respond_to?(name)) ||
                  proc { |parent| parent.table[name] }
    end

    def attr_from(bindable)
      call(*args.map { |arg| bindable.send(arg) })
    end

  end
end
require 'action_view'

module ActionView::Helpers::Tags
  # TODO: Find a better way to solve this issue!
  # This patch is needed since this Rails commit:
  # https://github.com/rails/rails/commit/c1a118a
  class Base
    private
    if defined? ::ActiveRecord
      if ::ActiveRecord::VERSION::STRING < '5.2'
        def value(object)
          object.send @method_name if object # use send instead of public_send
        end
      else # rails/rails#29791
        def value
          if @allow_method_names_outside_object
            object.send @method_name if object && object.respond_to?(@method_name, true)
          else
            object.send @method_name if object
          end
        end
      end
    end
  end
end

RANSACK_FORM_BUILDER = 'RANSACK_FORM_BUILDER'.freeze

require 'simple_form' if
  (ENV[RANSACK_FORM_BUILDER] || ''.freeze).match('SimpleForm'.freeze)

module Ransack
  module Helpers
    class FormBuilder < (ENV[RANSACK_FORM_BUILDER].try(:constantize) ||
      ActionView::Helpers::FormBuilder)

      def label(method, *args, &block)
        options = args.extract_options!
        text = args.first
        i18n = options[:i18n] || {}
        text ||= object.translate(
          method, i18n.reverse_merge(:include_associations => true)
          ) if object.respond_to? :translate
        super(method, text, options, &block)
      end

      def submit(value = nil, options = {})
        value, options = nil, value if value.is_a?(Hash)
        value ||= Translate.word(:search).titleize
        super(value, options)
      end

      def attribute_select(options = nil, html_options = nil, action = nil)
        options = options || {}
        html_options = html_options || {}
        action = action || Constants::SEARCH
        default = options.delete(:default)
        raise ArgumentError, formbuilder_error_message(
          "#{action}_select") unless object.respond_to?(:context)
        options[:include_blank] = true unless options.has_key?(:include_blank)
        bases = [''.freeze].freeze + association_array(options[:associations])
        if bases.size > 1
          collection = attribute_collection_for_bases(action, bases)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection.flatten(2))
            )
          template_grouped_collection_select(collection, options, html_options)
        else
          collection = collection_for_base(action, bases.first)
          object.name ||= default if can_use_default?(
            default, :name, mapped_values(collection)
            )
          template_collection_select(:name, collection, options, html_options)
        end
      end

      def sort_direction_select(options = {}, html_options = {})
        unless object.respond_to?(:context)
          raise ArgumentError,
          formbuilder_error_message('sort_direction'.freeze)
        end
        template_collection_select(:dir, sort_array, options, html_options)
      end

      def sort_select(options = {}, html_options = {})
        attribute_select(options, html_options, 'sort'.freeze) +
        sort_direction_select(options, html_options)
      end

      def sort_fields(*args, &block)
        search_fields(:s, args, block)
      end

      def sort_link(attribute, *args)
        @template.sort_link @object, attribute, *args
      end

      def sort_url(attribute, *args)
        @template.sort_url @object, attribute, *args
      end

      def condition_fields(*args, &block)
        search_fields(:c, args, block)
      end

      def grouping_fields(*args, &block)
        search_fields(:g, args, block)
      end

      def attribute_fields(*args, &block)
        search_fields(:a, args, block)
      end

      def predicate_fields(*args, &block)
        search_fields(:p, args, block)
      end

      def value_fields(*args, &block)
        search_fields(:v, args, block)
      end

      def search_fields(name, args, block)
        args << {} unless args.last.is_a?(Hash)
        args.last[:builder] ||= options[:builder]
        args.last[:parent_builder] = self
        options = args.extract_options!
        objects = args.shift
        objects ||= @object.send(name)
        objects = [objects] unless Array === objects
        name = "#{options[:object_name] || object_name}[#{name}]"
        objects.inject(ActiveSupport::SafeBuffer.new) do |output, child|
          output << @template.fields_for("#{name}[#{options[:child_index] ||
          nested_child_index(name)}]", child, options, &block)
        end
      end

      def predicate_select(options = {}, html_options = {})
        options[:compounds] = true if options[:compounds].nil?
        default = options.delete(:default) || Constants::CONT

        keys =
        if options[:compounds]
          Predicate.names
        else
          Predicate.names.reject { |k| k.match(/_(any|all)$/) }
        end
        if only = options[:only]
          if only.respond_to? :call
            keys = keys.select { |k| only.call(k) }
          else
            only = Array.wrap(only).map(&:to_s)
            keys = keys.select {
              |k| only.include? k.sub(/_(any|all)$/, ''.freeze)
            }
          end
        end
        collection = keys.map { |k| [k, Translate.predicate(k)] }
        object.predicate ||= Predicate.named(default) if
          can_use_default?(default, :predicate, keys)
        template_collection_select(:p, collection, options, html_options)
      end

      def combinator_select(options = {}, html_options = {})
        template_collection_select(
          :m, combinator_choices, options, html_options)
      end

      private

      def template_grouped_collection_select(collection, options, html_options)
        @template.grouped_collection_select(
          @object_name, :name, collection, :last, :first, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def template_collection_select(name, collection, options, html_options)
        @template.collection_select(
          @object_name, name, collection, :first, :last,
          objectify_options(options), @default_options.merge(html_options)
          )
      end

      def can_use_default?(default, attribute, values)
        object.respond_to?("#{attribute}=") && default &&
          values.include?(default.to_s)
      end

      def mapped_values(values)
        values.map { |v| v.is_a?(Array) ? v.first : nil }.compact
      end

      def sort_array
        [
          ['asc'.freeze,  object.translate('asc'.freeze)].freeze,
          ['desc'.freeze, object.translate('desc'.freeze)].freeze
        ].freeze
      end

      def combinator_choices
        if Nodes::Condition === object
          [
            [Constants::OR,  Translate.word(:any)],
            [Constants::AND, Translate.word(:all)]
          ]
        else
          [
            [Constants::AND, Translate.word(:all)],
            [Constants::OR,  Translate.word(:any)]
          ]
        end
      end

      def association_array(obj, prefix = nil)
        ([prefix] + association_object(obj))
        .compact
        .flat_map { |v| [prefix, v].compact.join(Constants::UNDERSCORE) }
      end

      def association_object(obj)
        case obj
        when Array
          obj
        when Hash
          association_hash(obj)
        else
          [obj]
        end
      end

      def association_hash(obj)
        obj.map do |key, value|
          case value
          when Array, Hash
            association_array(value, key.to_s)
          else
            [key.to_s, [key, value].join(Constants::UNDERSCORE)]
          end
        end
      end

      def attribute_collection_for_bases(action, bases)
        bases.map { |base| get_attribute_element(action, base) }.compact
      end

      def get_attribute_element(action, base)
        begin
          [
            Translate.association(base, :context => object.context),
            collection_for_base(action, base)
          ]
        rescue UntraversableAssociationError
          nil
        end
      end

      def attribute_collection_for_base(attributes, base = nil)
        attributes.map do |c|
          [
            attr_from_base_and_column(base, c),
            Translate.attribute(
              attr_from_base_and_column(base, c), :context => object.context
            )
          ]
        end
      end

      def collection_for_base(action, base)
        attribute_collection_for_base(
          object.context.send("#{action}able_attributes", base), base)
      end

      def attr_from_base_and_column(base, column)
        [base, column].reject(&:blank?).join(Constants::UNDERSCORE)
      end

      def formbuilder_error_message(action)
        "#{action.sub(Constants::SEARCH, Constants::ATTRIBUTE)
          } must be called inside a search FormBuilder!"
      end

    end
  end
end
